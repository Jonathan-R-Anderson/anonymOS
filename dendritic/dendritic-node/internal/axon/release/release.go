// Package release is P16's signed-release verifier: T16.1 and E16.3.
//
// §18.14 names the update channel as the strongest adversary against a real
// deployment, and it is the one adversary Constitution §7 omits. If it fails,
// every other property in the document is void — an attacker who ships the
// binary does not need to break the onion routing, and no amount of work in
// Parts I–IV compensates.
//
// WHAT WAS ACTUALLY THERE, BEFORE THIS PACKAGE. §23's P16 card credits the tree
// with "dist/ (7 platform binaries with .sha256)" and observes that "a .sha256
// beside a binary is not a signature". It was worse than that:
// `scripts/build-release.sh` emitted **no checksums at all**, and
// `scripts/update-from-github.sh` downloaded and installed with **no
// verification of any kind** — no hash, no signature, no version check. The
// update path trusted whatever the network returned.
//
// THREE RULES, AND EACH ONE IS A CLASS OF ATTACK:
//
//	FAIL CLOSED       every error refuses. There is no "warn and continue" and
//	                  no partial success, because an updater that proceeds on a
//	                  verification error is an updater with no verification.
//	PINNED KEYS       the verifying key is COMPILED IN, never fetched. A key
//	                  retrieved over the same channel as the binary is signed by
//	                  whoever controls that channel.
//	SIGN THE SET      the signature covers the whole manifest, not each file
//	                  separately, so removing or substituting an entry is
//	                  detected. Per-file signatures let an attacker serve an old
//	                  file that was validly signed once.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Artifact is one file in a release.
type Artifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is the signed statement about a release.
//
// It carries the version and the full artifact set. Both are inside the
// signature: a manifest that signed only the hashes would let an attacker
// replay an old release's signature under a new version number, which is the
// downgrade attack with extra steps.
type Manifest struct {
	// Version is a monotonically increasing release version, e.g. "1.4.2".
	Version string `json:"version"`
	// BuiltAt is an RFC 3339 timestamp. It is informational and is NOT used for
	// any decision: a timestamp an attacker supplies is not a freshness proof.
	BuiltAt string `json:"built_at"`
	// Artifacts is the complete set, sorted by name for a canonical encoding.
	Artifacts []Artifact `json:"artifacts"`
	// KeyID identifies which pinned key signed this, so keys can be rotated
	// without a flag day.
	KeyID string `json:"key_id"`
}

// SignedManifest is a manifest plus its detached signature.
type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"` // hex ed25519
}

var (
	// ErrNoSignature means the release carries no signature at all. It is
	// listed first because it is the case an updater is most likely to treat as
	// "nothing to check".
	ErrNoSignature = errors.New("axon/release: release is unsigned")
	// ErrUnknownKey means the manifest names a key this build does not pin.
	ErrUnknownKey = errors.New("axon/release: manifest signed by an unpinned key")
	// ErrBadSignature means the signature does not verify.
	ErrBadSignature = errors.New("axon/release: manifest signature does not verify")
	// ErrArtifactMissing means the manifest names a file the release does not
	// contain.
	ErrArtifactMissing = errors.New("axon/release: manifest names a missing artifact")
	// ErrArtifactExtra means the release contains a file the manifest does not
	// name. It is an error, not a curiosity: an extra file in a release is a
	// file nobody signed.
	ErrArtifactExtra = errors.New("axon/release: release contains an unsigned artifact")
	// ErrArtifactCorrupt means a file's hash or size does not match.
	ErrArtifactCorrupt = errors.New("axon/release: artifact does not match the manifest")
	// ErrDowngrade means the release is older than what is installed.
	ErrDowngrade = errors.New("axon/release: release is older than the installed version")
	// ErrMalformed means the manifest could not be parsed or is internally
	// inconsistent.
	ErrMalformed = errors.New("axon/release: manifest is malformed")
)

// Keyring is the set of pinned release keys.
//
// It is a value rather than a package-level variable so a test can construct
// one, and production builds it from compiled-in constants. There is no method
// to add a key from a file or a URL, and that absence is the design.
type Keyring struct {
	keys map[string]ed25519.PublicKey
}

// NewKeyring pins a set of keys.
func NewKeyring(keys map[string]ed25519.PublicKey) *Keyring {
	k := &Keyring{keys: make(map[string]ed25519.PublicKey, len(keys))}
	for id, pub := range keys {
		k.keys[id] = append(ed25519.PublicKey(nil), pub...)
	}
	return k
}

// Len is the number of pinned keys.
func (k *Keyring) Len() int { return len(k.keys) }

// signingBytes is the canonical encoding that is actually signed.
//
// It is built by hand rather than by json.Marshal because a signature over
// "whatever the JSON encoder produced" is a signature over an encoder version.
// Two Go releases that order or escape differently would produce two different
// signed byte strings for one manifest, and the failure would look like a
// tampered release.
func signingBytes(m Manifest) []byte {
	var b bytes.Buffer
	b.WriteString("axon-release-v1\n")
	b.WriteString("version:" + m.Version + "\n")
	b.WriteString("key:" + m.KeyID + "\n")
	b.WriteString("built:" + m.BuiltAt + "\n")

	arts := append([]Artifact(nil), m.Artifacts...)
	sort.Slice(arts, func(i, j int) bool { return arts[i].Name < arts[j].Name })
	b.WriteString("count:" + strconv.Itoa(len(arts)) + "\n")
	for _, a := range arts {
		// Each field is length-prefixed via the separators, and the name is
		// last-but-one so a name containing a newline cannot forge a second
		// entry. Names are also validated in Verify.
		b.WriteString(a.SHA256 + " " + strconv.FormatInt(a.Size, 10) + " " + a.Name + "\n")
	}
	return b.Bytes()
}

// Sign produces a signed manifest. Used by the build, and by tests.
func Sign(m Manifest, keyID string, priv ed25519.PrivateKey) (SignedManifest, error) {
	if keyID == "" {
		return SignedManifest{}, fmt.Errorf("%w: empty key id", ErrMalformed)
	}
	m.KeyID = keyID
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].Name < m.Artifacts[j].Name })
	sig := ed25519.Sign(priv, signingBytes(m))
	return SignedManifest{Manifest: m, Signature: hex.EncodeToString(sig)}, nil
}

// Encode renders a signed manifest for distribution.
func Encode(sm SignedManifest) ([]byte, error) { return json.MarshalIndent(sm, "", "  ") }

// Decode parses a distributed manifest.
func Decode(b []byte) (SignedManifest, error) {
	var sm SignedManifest
	if err := json.Unmarshal(b, &sm); err != nil {
		return SignedManifest{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return sm, nil
}

// Opener yields the bytes of one artifact. The verifier reads every artifact it
// is asked to check; there is no "trust the size" shortcut.
type Opener func(name string) (io.ReadCloser, error)

// Verify checks a release and returns nil ONLY if everything holds.
//
// installed is the currently installed version, or "" on a first install.
// present is the set of artifact names the release actually contains.
//
// THE ORDER IS DELIBERATE: signature first, then contents. Hashing megabytes of
// attacker-supplied data before establishing that anyone vouched for it is work
// an attacker gets for free, and a verifier that reports "corrupt artifact"
// before "unsigned release" tells an attacker which of its two problems to fix.
func Verify(sm SignedManifest, ring *Keyring, installed string, present []string, open Opener) error {
	if sm.Signature == "" {
		return ErrNoSignature
	}
	sig, err := hex.DecodeString(sm.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is not %d hex bytes", ErrBadSignature, ed25519.SignatureSize)
	}
	pub, ok := ring.keys[sm.Manifest.KeyID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKey, sm.Manifest.KeyID)
	}
	if !ed25519.Verify(pub, signingBytes(sm.Manifest), sig) {
		return ErrBadSignature
	}

	// Structural checks on the now-authenticated manifest.
	if sm.Manifest.Version == "" {
		return fmt.Errorf("%w: no version", ErrMalformed)
	}
	seen := map[string]bool{}
	for _, a := range sm.Manifest.Artifacts {
		if a.Name == "" || strings.ContainsAny(a.Name, "\n\r/\\") {
			// A name with a separator in it is a path-traversal primitive on the
			// install side, and a name with a newline could forge an entry in
			// the signing encoding.
			return fmt.Errorf("%w: artifact name %q", ErrMalformed, a.Name)
		}
		if seen[a.Name] {
			return fmt.Errorf("%w: duplicate artifact %q", ErrMalformed, a.Name)
		}
		seen[a.Name] = true
		if a.Size < 0 {
			return fmt.Errorf("%w: negative size for %q", ErrMalformed, a.Name)
		}
		if len(a.SHA256) != 64 {
			return fmt.Errorf("%w: %q has a %d-char digest", ErrMalformed, a.Name, len(a.SHA256))
		}
	}

	// Rollback. An attacker who cannot forge a signature can still replay an
	// OLD, validly signed release with a known vulnerability, and that is the
	// cheapest attack available against a fail-closed updater.
	if installed != "" {
		cmp, err := CompareVersions(sm.Manifest.Version, installed)
		if err != nil {
			return err
		}
		if cmp < 0 {
			return fmt.Errorf("%w: offered %s, installed %s",
				ErrDowngrade, sm.Manifest.Version, installed)
		}
	}

	// The artifact set must match exactly, in both directions.
	have := map[string]bool{}
	for _, n := range present {
		have[n] = true
	}
	for _, a := range sm.Manifest.Artifacts {
		if !have[a.Name] {
			return fmt.Errorf("%w: %q", ErrArtifactMissing, a.Name)
		}
	}
	for n := range have {
		if !seen[n] {
			return fmt.Errorf("%w: %q", ErrArtifactExtra, n)
		}
	}

	// Contents.
	for _, a := range sm.Manifest.Artifacts {
		rc, err := open(a.Name)
		if err != nil {
			return fmt.Errorf("%w: %q: %v", ErrArtifactMissing, a.Name, err)
		}
		h := sha256.New()
		n, err := io.Copy(h, rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("%w: %q: %v", ErrArtifactCorrupt, a.Name, err)
		}
		if n != a.Size {
			return fmt.Errorf("%w: %q is %d bytes, manifest says %d",
				ErrArtifactCorrupt, a.Name, n, a.Size)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != a.SHA256 {
			return fmt.Errorf("%w: %q digest %s, manifest says %s",
				ErrArtifactCorrupt, a.Name, got, a.SHA256)
		}
	}
	return nil
}

// CompareVersions compares dotted numeric versions. -1, 0, +1.
//
// It is deliberately strict: a version it cannot parse is an error rather than
// a comparison that happens to succeed. A lenient comparator is how a downgrade
// check gets bypassed by a version string like "1.4.2-attacker".
func CompareVersions(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func parseVersion(v string) ([]int, error) {
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return nil, fmt.Errorf("%w: empty version", ErrMalformed)
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: version %q has a non-numeric component %q", ErrMalformed, v, p)
		}
		out = append(out, n)
	}
	return out, nil
}
