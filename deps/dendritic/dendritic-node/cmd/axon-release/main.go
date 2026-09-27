// Command axon-release builds, signs and verifies release manifests.
//
// It exists because `scripts/build-release.sh` produced seven binaries and
// nothing else — no checksums, no manifest, no signature — and
// `scripts/update-from-github.sh` installed whatever the network returned with
// no verification of any kind. §18.14 names the update channel as the strongest
// adversary against a real deployment, and it was completely open.
//
//	axon-release manifest -dir dist -version 1.4.2 -out dist/manifest.json
//	axon-release sign     -in dist/manifest.json -key release.key -id release-2026
//	axon-release verify   -in dist/manifest.json -dir dist -pub release.pub [-installed 1.4.1]
//	axon-release keygen   -out release            # writes release.key and release.pub
//
// THE SPLIT BETWEEN `manifest` AND `sign` IS DELIBERATE. A build can compute
// hashes; only a keyholder can sign. Merging them would put the signing key on
// the build machine, which is the machine an attacker who has compromised the
// build already owns.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "manifest":
		err = cmdManifest(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "axon-release:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: axon-release {manifest|sign|verify|keygen} [flags]")
	os.Exit(2)
}

// artifactsIn lists the release files in a directory.
//
// It skips the manifest itself and any signature, and it skips nothing else:
// an unexpected file in dist/ is a file that will ship, and Verify treats an
// artifact the manifest does not name as an error precisely so that it cannot.
func artifactsIn(dir string) ([]release.Artifact, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []release.Artifact
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "manifest.json" || strings.HasSuffix(name, ".sig") ||
			strings.HasSuffix(name, ".sha256") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, release.Artifact{
			Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil, fmt.Errorf("no artifacts in %s", dir)
	}
	return out, nil
}

func cmdManifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	dir := fs.String("dir", "dist", "directory of release artifacts")
	version := fs.String("version", "", "release version, e.g. 1.4.2")
	out := fs.String("out", "", "output path (default <dir>/manifest.json)")
	fs.Parse(args)
	if *version == "" {
		return fmt.Errorf("-version is required")
	}
	if _, err := release.CompareVersions(*version, *version); err != nil {
		return err
	}
	arts, err := artifactsIn(*dir)
	if err != nil {
		return err
	}
	m := release.Manifest{
		Version:   *version,
		BuiltAt:   time.Now().UTC().Format(time.RFC3339),
		Artifacts: arts,
	}
	// Written UNSIGNED, with an empty signature. An unsigned manifest is
	// refused by Verify with ErrNoSignature rather than being treated as
	// "nothing to check", so shipping this by mistake fails closed.
	b, err := release.Encode(release.SignedManifest{Manifest: m})
	if err != nil {
		return err
	}
	path := *out
	if path == "" {
		path = filepath.Join(*dir, "manifest.json")
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d artifacts, version %s (UNSIGNED)\n", path, len(arts), *version)
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	in := fs.String("in", "dist/manifest.json", "manifest to sign, in place")
	keyPath := fs.String("key", "", "ed25519 private key file (hex)")
	id := fs.String("id", "", "key id recorded in the manifest")
	fs.Parse(args)
	if *keyPath == "" || *id == "" {
		return fmt.Errorf("-key and -id are required")
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("key must be %d hex-encoded bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	sm, err := release.Decode(b)
	if err != nil {
		return err
	}
	signed, err := release.Sign(sm.Manifest, *id, priv)
	if err != nil {
		return err
	}
	out, err := release.Encode(signed)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*in, out, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s as %s (version %s)\n", *in, *id, signed.Manifest.Version)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	in := fs.String("in", "dist/manifest.json", "signed manifest")
	dir := fs.String("dir", "dist", "directory of release artifacts")
	pubPath := fs.String("pub", "", "pinned public key file (hex)")
	id := fs.String("id", "", "expected key id (default: whatever the file is named)")
	installed := fs.String("installed", "", "currently installed version, for the rollback check")
	fs.Parse(args)
	if *pubPath == "" {
		return fmt.Errorf("-pub is required; a verifier with no pinned key verifies nothing")
	}
	raw, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}

	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	sm, err := release.Decode(b)
	if err != nil {
		return err
	}
	keyID := *id
	if keyID == "" {
		keyID = sm.Manifest.KeyID
	}
	ring := release.NewKeyring(map[string]ed25519.PublicKey{keyID: ed25519.PublicKey(pub)})

	arts, err := artifactsIn(*dir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(arts))
	for _, a := range arts {
		names = append(names, a.Name)
	}
	open := func(name string) (io.ReadCloser, error) {
		return os.Open(filepath.Join(*dir, name))
	}
	if err := release.Verify(sm, ring, *installed, names, open); err != nil {
		return err // non-zero exit: FAIL CLOSED
	}
	fmt.Printf("OK: %s version %s, %d artifacts, signed by %s\n",
		*in, sm.Manifest.Version, len(sm.Manifest.Artifacts), sm.Manifest.KeyID)
	return nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "release", "output prefix; writes <out>.key and <out>.pub")
	fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// 0600 on the private key. A release signing key readable by the build user
	// is a release signing key owned by anyone who compromises the build.
	if err := os.WriteFile(*out+".key", []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (0600) and %s.pub\n", *out, *out)
	fmt.Println("PIN THE PUBLIC KEY IN THE CLIENT. A key fetched over the same channel")
	fmt.Println("as the binary is signed by whoever controls that channel.")
	return nil
}
