package token

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// dataPath is what S10 is about: the packages that relay, store and resolve.
//
// internal/channel is deliberately NOT here. It is the SCPP/1 payment-channel
// system — an "insufficient funds" error in it is the thing working, not a
// data-path refusal — and an audit that could not tell a payment system from a
// payment on the data path would either fail permanently or be deleted.
var dataPath = []string{
	filepath.Join(".."),                    // internal/axon
	filepath.Join("..", "..", "store"),     // the shard store
	filepath.Join("..", "..", "p2p"),       // dispersal and recall
	filepath.Join("..", "..", "dcs"),       // the distributed content service
	filepath.Join("..", "..", "placement"), // shard placement
}

// inSelf reports whether a walked path is this package's own source. The walk
// starts at internal/axon, so this package appears as "../token/...", not as
// something containing "/axon/token/" -- a substring check on the absolute-
// looking form silently matches nothing and the audit then flags its own
// regexes, which is how this was found.
func inSelf(path string) bool {
	dir := filepath.ToSlash(filepath.Dir(path))
	return dir == "../token" || strings.HasSuffix(dir, "/axon/token") || dir == "."
}

func axonFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, root := range dataPath {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no data-path files found -- the audit is looking in the wrong place")
	}
	return out
}

// TestT152NothingOnTheDataPathImportsThisPackage is T15.2's structural half.
//
// "A build with the token package removed still relays, stores and resolves —
// falsified by any payment-required error (S10)."
//
// The empirical half is `removability_test.sh`, which actually deletes the
// package and builds. This half is what makes that result STABLE: a later edit
// that imports this package from the data path would pass every functional test
// and quietly make payments load-bearing, and the failure would surface as a
// user unable to browse rather than as a broken build.
//
// §4's layering rule is the same requirement from the other side: the
// accounting plane must not become a routing input.
func TestT152NothingOnTheDataPathImportsThisPackage(t *testing.T) {
	const self = "internal/axon/token"
	fset := token.NewFileSet()

	for _, path := range axonFiles(t) {
		if inSelf(path) {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			continue
		}
		for _, imp := range f.Imports {
			if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), self) {
				t.Errorf("T15.2 violated: %s imports the token package. "+
					"The data path must run with payments absent; an import here "+
					"makes the subsystem load-bearing and E15.1 unprovable.", path)
			}
		}
	}
}

// TestS10NoPaymentRequiredErrorExistsAnywhere is S10.
//
// The criterion is "falsified by any payment-required error". So the audit
// looks for the error itself, across the whole AXON tree — not for an import,
// which the previous test covers, but for the SHAPE of a data-path refusal
// conditioned on payment.
func TestS10NoPaymentRequiredErrorExistsAnywhere(t *testing.T) {
	banned := regexp.MustCompile(`(?i)payment\s+required|paymentrequired|` +
		`insufficient\s+(credit|balance|funds)|` +
		`err(no)?(tokens?|credit|payment)\w*\s*=\s*errors\.New`)
	for _, path := range axonFiles(t) {
		if inSelf(path) {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !banned.MatchString(line) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			t.Errorf("S10 violated: %s:%d can refuse a data-path operation for "+
				"want of payment:\n\t%s", path, i+1, strings.TrimSpace(line))
		}
	}
}

// TestMustNotBeBuiltYet is P15's own prohibition list, as a test.
//
// §23's P15 card: "Must NOT be built yet — any token-price mechanism, exchange
// or market (Constitution §8). Payment as a routing input (§4's layering rule).
// Mandatory payment for any data-path operation, ever."
//
// The third is "ever", not "yet", and the audit does not distinguish them: a
// prohibition with an expiry date and one without look identical in code, and
// the one that expires is the one somebody removes early.
func TestMustNotBeBuiltYet(t *testing.T) {
	// A price mechanism, an exchange, a market.
	market := regexp.MustCompile(`(?i)\b(exchange\s?rate|price\s?feed|oracle|` +
		`orderbook|order\s?book|market\s?maker|swap|liquidity)\b`)
	// Payment as a routing input: this package must never learn what a route is.
	routing := regexp.MustCompile(`(?i)\b(selectpath|routingweight|pathweight|` +
		`relayweight|selectionweight)\b`)

	var files []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil || len(files) == 0 {
		t.Fatalf("walk: %v", err)
	}

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if m := market.FindString(line); m != "" {
				t.Errorf("§8 violated: %s:%d builds a price mechanism (%q):\n\t%s",
					path, i+1, m, strings.TrimSpace(line))
			}
			if m := routing.FindString(line); m != "" {
				t.Errorf("§4 violated: %s:%d makes payment a routing input (%q):\n\t%s",
					path, i+1, m, strings.TrimSpace(line))
			}
		}
	}

	// And the reverse direction: the path selector must not learn about tokens.
	// §4's layering rule is symmetric and this is the half that would be added
	// by someone trying to be helpful about relay incentives.
	fset := token.NewFileSet()
	for _, path := range axonFiles(t) {
		p := filepath.ToSlash(path)
		if !strings.Contains(p, "/axon/path/") && !strings.Contains(p, "/axon/profile/") &&
			!strings.Contains(p, "/axon/tunnel/") && !strings.Contains(p, "/axon/dht/") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			continue
		}
		for _, imp := range f.Imports {
			ip := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(ip, "axon/token") || strings.Contains(ip, "internal/channel") {
				t.Errorf("§4 violated: %s imports %q -- the accounting plane has "+
					"become a routing input", path, ip)
			}
		}
	}
}

// TestNoTokenRidesOnTheCriticalPathByDefault checks the architecture claim.
//
// §23's P15: "the data path has no payment call at all, which is what makes the
// subsystem removable". Accept() exists for a relay that CHOOSES to charge; the
// property is that no cell-forwarding code calls it.
func TestNoTokenRidesOnTheCriticalPathByDefault(t *testing.T) {
	callers := regexp.MustCompile(`\btoken\.(Accept|Redeem|Issue)\b`)
	for _, path := range axonFiles(t) {
		if inSelf(path) {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if m := callers.FindString(string(src)); m != "" {
			t.Errorf("%s calls %s outside the token package", path, m)
		}
	}
}
