package profile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// axonRoot is internal/axon, from this package's directory.
const axonRoot = ".."

// goFilesUnder lists every .go file under a directory, tests included.
func goFilesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if len(out) == 0 {
		t.Fatalf("no Go files under %s -- the audit is looking in the wrong place", dir)
	}
	return out
}

// scoringPathFiles is every non-test source file that can influence a profile:
// this package, plus anything under internal/axon that imports it.
//
// Test files are excluded deliberately. A test that names a self-report in
// order to prove it is ignored — E12a.1 does exactly that — is the evidence,
// not the violation, and an audit that could not tell them apart would push the
// proof out of the tree.
func scoringPathFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	for _, path := range goFilesUnder(t, axonRoot) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		if strings.HasPrefix(filepath.ToSlash(path), "../profile/") {
			out = append(out, path)
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			continue
		}
		for _, imp := range f.Imports {
			if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), "internal/axon/profile") {
				out = append(out, path)
				break
			}
		}
	}
	return out
}

// TestT12a1ProfilesHaveNoNetworkInput is T12a.1.
//
// A profile must be derived only from observations this node made itself. The
// enforcement is at the import graph rather than in review: this package may not
// import anything that could deliver another node's opinion, so there is no
// call site at which a foreign profile could enter, whatever a future edit
// intends.
//
// params is permitted because it is a leaf of compile-time constants with no
// I/O of any kind. Everything else on this list is forbidden by category, not
// by name, so a new networking library does not slip through:
func TestT12a1ProfilesHaveNoNetworkInput(t *testing.T) {
	forbiddenPrefixes := []string{
		"net", "net/http", "os", "io", "bufio",
		"encoding/", "github.com/fxamacker/cbor",
		"github.com/libp2p", "google.golang.org/protobuf",
	}
	// Sibling AXON packages that carry wire formats. Importing any of them
	// would put a decoder one call away from the scoring path.
	forbiddenSiblings := []string{
		"internal/axon/link", "internal/axon/dht", "internal/axon/rendez",
		"internal/axon/circuit", "internal/axon/peer", "internal/p2p",
		"internal/store", "internal/dcs",
	}

	fset := token.NewFileSet()
	for _, path := range goFilesUnder(t, ".") {
		if strings.HasSuffix(path, "_test.go") {
			continue // the audit itself parses source; the package under audit does not
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenPrefixes {
				if p == bad || strings.HasPrefix(p, bad) {
					t.Errorf("T12a.1 violated: %s imports %q, which can carry another node's data", path, p)
				}
			}
			for _, bad := range forbiddenSiblings {
				if strings.Contains(p, bad) {
					t.Errorf("T12a.1 violated: %s imports the wire package %q", path, p)
				}
			}
		}
	}
}

// TestT12a3ProfilesAreNeverSerialised is T12a.3.
//
// Two halves, because either alone is insufficient:
//
//	(a) nothing in this package can be marshalled -- no struct tag, no
//	    Marshal/Encode method, no marshaller interface satisfied;
//	(b) no wire type ANYWHERE under internal/axon has a field whose type comes
//	    from this package.
//
// (a) alone would miss a wire struct that embeds a Profile and gets encoded by
// the enclosing type's tags. (b) alone would miss this package growing its own
// Encode. A capacity tier is a fingerprint of this node's own traffic, so the
// property being protected is that it has no way out at all.
func TestT12a3ProfilesAreNeverSerialised(t *testing.T) {
	// (a) no serialisation surface in this package.
	tags := regexp.MustCompile(`(?:cbor|json|protobuf|msgpack|bson|xml):"`)
	methods := regexp.MustCompile(`func \([^)]*\*?(?:Profile|Profiles|Tier|ObservationKind)\) (Marshal\w*|Encode\w*|Append\w*|WriteTo)\(`)
	for _, path := range goFilesUnder(t, ".") {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if m := tags.FindString(string(src)); m != "" {
			t.Errorf("T12a.3 violated: %s carries a %s serialisation tag", path, m)
		}
		if m := methods.FindString(string(src)); m != "" {
			t.Errorf("T12a.3 violated: %s defines a serialiser: %s", path, m)
		}
	}

	// (b) no wire type anywhere under internal/axon names one of our types.
	ours := map[string]bool{
		"Profile": true, "Profiles": true, "Tier": true,
		"ObservationKind": true, "decayed": true,
	}
	fset := token.NewFileSet()
	for _, path := range goFilesUnder(t, axonRoot) {
		if strings.HasPrefix(filepath.ToSlash(path), "../profile/") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			continue // packages that do not parse are somebody else's failing test
		}
		// Does this file even reference the profile package?
		refs := false
		for _, imp := range f.Imports {
			if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), "internal/axon/profile") {
				refs = true
			}
		}
		if !refs {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				if fld.Tag != nil && tags.MatchString(fld.Tag.Value) {
					if sel, ok := fld.Type.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "profile" && ours[sel.Sel.Name] {
							t.Errorf("T12a.3 violated: %s has a serialised field of type profile.%s",
								path, sel.Sel.Name)
						}
					}
				}
			}
			return true
		})
	}
}

// TestT12a4ClaimedBandwidthIsNotAnInput is T12a.4, by source audit.
//
// The self-report is the thing this package exists to stop trusting, and the
// way it would come back is not a deliberate decision but a convenience: a
// descriptor is already in hand at the call site, it has a bandwidth field, and
// blending it in "just as a prior" looks harmless. It is not -- a prior an
// adversary sets is an adversary-set weight with extra steps.
// The audited set is DERIVED, not listed: this package plus every non-test file
// under internal/axon that imports it. So when P12's selector starts calling
// Observe, it comes under this audit automatically, and there is no list for a
// later phase to forget to update.
func TestT12a4ClaimedBandwidthIsNotAnInput(t *testing.T) {
	banned := regexp.MustCompile(`(?i)claimed_?bw|claimedbandwidth|claimed_bandwidth|advertised_?bw|self_?report`)
	scoringPath := scoringPathFiles(t)
	if len(scoringPath) == 0 {
		t.Fatal("audit found no scoring-path files")
	}
	for _, path := range scoringPath {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !banned.MatchString(line) {
				continue
			}
			// A comment saying it is NOT used is the documentation this phase
			// asked for; code using it is the violation.
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			t.Errorf("T12a.4 violated: %s:%d uses a self-reported figure:\n\t%s", path, i+1, trimmed)
		}
	}
}

// TestPar03NoSharingSurface is P12a's "must NOT be built yet".
//
// Inter-node sharing of profiles is forbidden ever, not merely for now:
// sharing recreates the global metric the whole design exists to avoid. This
// checks the package exposes no method that would take or emit another node's
// view.
func TestPar03NoSharingSurface(t *testing.T) {
	banned := regexp.MustCompile(`func \(p \*Profiles\) (Merge|Import|Export|Gossip|Publish|Share|FromWire|ToWire|Unmarshal|Marshal)\w*\(`)
	for _, path := range goFilesUnder(t, ".") {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if m := banned.FindString(string(src)); m != "" {
			t.Errorf("PAR-03 violated: %s exposes a sharing surface: %s", path, m)
		}
	}
}
