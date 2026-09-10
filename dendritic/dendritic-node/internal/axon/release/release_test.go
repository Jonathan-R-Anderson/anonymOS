package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

// fixture builds a signed release over a set of files.
type fixture struct {
	ring  *Keyring
	priv  ed25519.PrivateKey
	sm    SignedManifest
	files map[string][]byte
}

func newFixture(t *testing.T, version string) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"syndichan-node-linux-amd64":  bytes.Repeat([]byte{0xAA}, 4096),
		"syndichan-node-linux-arm64":  bytes.Repeat([]byte{0xBB}, 2048),
		"syndichan-node-darwin-arm64": bytes.Repeat([]byte{0xCC}, 3072),
	}
	m := Manifest{Version: version, BuiltAt: "2026-08-16T12:00:00Z"}
	for name, b := range files {
		sum := sha256.Sum256(b)
		m.Artifacts = append(m.Artifacts, Artifact{
			Name: name, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:]),
		})
	}
	sm, err := Sign(m, "release-2026", priv)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		ring:  NewKeyring(map[string]ed25519.PublicKey{"release-2026": pub}),
		priv:  priv,
		sm:    sm,
		files: files,
	}
}

func (f *fixture) names() []string {
	out := make([]string, 0, len(f.files))
	for n := range f.files {
		out = append(out, n)
	}
	return out
}

func (f *fixture) open(name string) (io.ReadCloser, error) {
	b, ok := f.files[name]
	if !ok {
		return nil, errors.New("no such artifact")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *fixture) verify(installed string) error {
	return Verify(f.sm, f.ring, installed, f.names(), f.open)
}

// TestGoodReleaseVerifies is the baseline. Without it every refusal below could
// be a verifier that refuses everything.
func TestGoodReleaseVerifies(t *testing.T) {
	f := newFixture(t, "1.4.2")
	if err := f.verify(""); err != nil {
		t.Fatalf("an honest release was refused: %v", err)
	}
	if err := f.verify("1.4.1"); err != nil {
		t.Fatalf("an upgrade was refused: %v", err)
	}
	if err := f.verify("1.4.2"); err != nil {
		t.Fatalf("a same-version reinstall was refused: %v", err)
	}
}

// TestT161UpdaterFailsClosed is T16.1 and E16.3.
//
// "The updater refuses an unsigned or wrongly-signed release and fails closed."
//
// Every axis an attacker controls gets its own case. The table is the test:
// a verifier is only as good as the attack it was written against, and a single
// "tampered binary" case would miss the manifest attacks entirely.
func TestT161UpdaterFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, f *fixture)
		want    error
		explain string
	}{
		{
			name:    "unsigned",
			mutate:  func(_ *testing.T, f *fixture) { f.sm.Signature = "" },
			want:    ErrNoSignature,
			explain: "the case an updater is most likely to treat as 'nothing to check'",
		},
		{
			name:   "signature is not hex",
			mutate: func(_ *testing.T, f *fixture) { f.sm.Signature = "not-a-signature" },
			want:   ErrBadSignature,
		},
		{
			name: "signature truncated",
			mutate: func(_ *testing.T, f *fixture) {
				f.sm.Signature = f.sm.Signature[:len(f.sm.Signature)-2]
			},
			want: ErrBadSignature,
		},
		{
			name: "signed by a key we do not pin",
			mutate: func(t *testing.T, f *fixture) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				sm, err := Sign(f.sm.Manifest, "attacker-key", priv)
				if err != nil {
					t.Fatal(err)
				}
				f.sm = sm
			},
			want:    ErrUnknownKey,
			explain: "a validly signed release, signed by the wrong person",
		},
		{
			name: "key id swapped to a pinned one, signature left alone",
			mutate: func(t *testing.T, f *fixture) {
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				sm, _ := Sign(f.sm.Manifest, "attacker-key", priv)
				sm.Manifest.KeyID = "release-2026" // claim the good key
				f.sm = sm
			},
			want:    ErrBadSignature,
			explain: "the key id is inside the signature, so relabelling breaks it",
		},
		{
			name:   "version bumped after signing",
			mutate: func(_ *testing.T, f *fixture) { f.sm.Manifest.Version = "9.9.9" },
			want:   ErrBadSignature,
		},
		{
			name: "an artifact's digest rewritten in the manifest",
			mutate: func(_ *testing.T, f *fixture) {
				f.sm.Manifest.Artifacts[0].SHA256 =
					"0000000000000000000000000000000000000000000000000000000000000000"
			},
			want: ErrBadSignature,
		},
		{
			name: "a BINARY replaced, manifest untouched",
			mutate: func(_ *testing.T, f *fixture) {
				f.files["syndichan-node-linux-amd64"] = bytes.Repeat([]byte{0xEE}, 4096)
			},
			want:    ErrArtifactCorrupt,
			explain: "the attack the whole package exists for: same size, different bytes",
		},
		{
			name: "a binary truncated",
			mutate: func(_ *testing.T, f *fixture) {
				f.files["syndichan-node-linux-arm64"] = []byte{0xBB}
			},
			want: ErrArtifactCorrupt,
		},
		{
			name: "a signed artifact removed from the release",
			mutate: func(_ *testing.T, f *fixture) {
				delete(f.files, "syndichan-node-darwin-arm64")
			},
			want: ErrArtifactMissing,
		},
		{
			name: "an UNSIGNED artifact added to the release",
			mutate: func(_ *testing.T, f *fixture) {
				f.files["syndichan-node-linux-amd64-backdoor"] = []byte("payload")
			},
			want:    ErrArtifactExtra,
			explain: "an extra file in a release is a file nobody signed; an installer that picks by name would take it",
		},
		{
			name: "an artifact name containing a path separator",
			mutate: func(t *testing.T, f *fixture) {
				m := f.sm.Manifest
				m.Artifacts = append(m.Artifacts, Artifact{
					Name: "../../etc/cron.d/x", Size: 1,
					SHA256: "00000000000000000000000000000000000000000000000000000000000000ff",
				})
				sm, _ := Sign(m, "release-2026", f.priv)
				f.sm = sm
			},
			want:    ErrMalformed,
			explain: "path traversal survives a valid signature; the signer is not the only check",
		},
		{
			name: "a duplicate artifact entry",
			mutate: func(t *testing.T, f *fixture) {
				m := f.sm.Manifest
				m.Artifacts = append(m.Artifacts, m.Artifacts[0])
				sm, _ := Sign(m, "release-2026", f.priv)
				f.sm = sm
			},
			want: ErrMalformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.4.2")
			tc.mutate(t, f)
			err := f.verify("1.4.1")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v\n%s", err, tc.want, tc.explain)
			}
		})
	}
}

// TestRollbackIsRefused is the attack a fail-closed verifier still admits.
//
// An attacker who cannot forge a signature can replay an OLD, validly signed
// release with a known vulnerability. Everything about it verifies, because it
// was genuine — the only thing wrong with it is that it is older.
func TestRollbackIsRefused(t *testing.T) {
	old := newFixture(t, "1.0.0")
	if err := Verify(old.sm, old.ring, "1.4.2", old.names(), old.open); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("a validly signed 1.0.0 was accepted over an installed 1.4.2: %v", err)
	}
	// A first install has nothing to compare against and must still work.
	if err := Verify(old.sm, old.ring, "", old.names(), old.open); err != nil {
		t.Fatalf("a first install of 1.0.0 was refused: %v", err)
	}
}

// TestVersionComparisonIsStrict covers the comparator the rollback check rests
// on.
//
// A lenient comparator is how a downgrade check gets bypassed: a version string
// the parser shrugs at compares as zero and every release looks like an upgrade.
func TestVersionComparisonIsStrict(t *testing.T) {
	ordered := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.10.0", "1.9.0", 1}, // not string order
		{"2.0", "1.99.99", 1},
		{"1.4", "1.4.0", 0}, // a missing component is zero
		{"v1.4.2", "1.4.2", 0},
	}
	for _, tc := range ordered {
		got, err := CompareVersions(tc.a, tc.b)
		if err != nil {
			t.Fatalf("CompareVersions(%q,%q): %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Fatalf("CompareVersions(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	for _, bad := range []string{"", "1.4.2-attacker", "latest", "1..2", "1.-2", "١.٤"} {
		if _, err := CompareVersions(bad, "1.0.0"); err == nil {
			t.Fatalf("CompareVersions accepted %q; a lenient parser bypasses the rollback check", bad)
		}
	}
}

// TestSigningEncodingIsCanonical guards the one thing that would break every
// signature at once.
//
// The signed bytes are built by hand rather than by json.Marshal. If they were
// not, a Go release that ordered or escaped differently would produce different
// signed bytes for the same manifest, and every honest release would start
// failing verification — presenting as a supply-chain attack.
func TestSigningEncodingIsCanonical(t *testing.T) {
	base := Manifest{
		Version: "1.0.0", BuiltAt: "t", KeyID: "k",
		Artifacts: []Artifact{
			{Name: "b", Size: 2, SHA256: "bb"},
			{Name: "a", Size: 1, SHA256: "aa"},
		},
	}
	shuffled := Manifest{
		Version: "1.0.0", BuiltAt: "t", KeyID: "k",
		Artifacts: []Artifact{
			{Name: "a", Size: 1, SHA256: "aa"},
			{Name: "b", Size: 2, SHA256: "bb"},
		},
	}
	if !bytes.Equal(signingBytes(base), signingBytes(shuffled)) {
		t.Fatal("artifact order changes the signed bytes; the encoding is not canonical")
	}

	// And two DIFFERENT manifests must not collide. The count line is what
	// stops an artifact set being reinterpreted as a longer or shorter one.
	other := base
	other.Artifacts = append(append([]Artifact(nil), base.Artifacts...),
		Artifact{Name: "c", Size: 3, SHA256: "cc"})
	if bytes.Equal(signingBytes(base), signingBytes(other)) {
		t.Fatal("adding an artifact did not change the signed bytes")
	}
}

// TestEncodeDecodeRoundTrips covers the distribution format.
func TestEncodeDecodeRoundTrips(t *testing.T) {
	f := newFixture(t, "1.4.2")
	b, err := Encode(f.sm)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(back, f.ring, "1.4.1", f.names(), f.open); err != nil {
		t.Fatalf("a round-tripped manifest failed to verify: %v", err)
	}
	if _, err := Decode([]byte("{not json")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed JSON gave %v", err)
	}
}

// TestKeyringCannotBeExtendedFromData is the pinning property.
//
// A key fetched over the same channel as the binary is signed by whoever
// controls that channel. The audit for this is structural — the type has no
// method that takes a filename or a URL — and this asserts the surface.
func TestKeyringCannotBeExtendedFromData(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k := NewKeyring(map[string]ed25519.PublicKey{"a": pub})
	if k.Len() != 1 {
		t.Fatalf("keyring holds %d keys", k.Len())
	}
	// The constructor copies, so a caller mutating its input afterwards cannot
	// change what is pinned.
	src := map[string]ed25519.PublicKey{"a": pub}
	k2 := NewKeyring(src)
	src["b"] = pub
	if k2.Len() != 1 {
		t.Fatal("mutating the constructor's input changed the pinned keyring")
	}
}
