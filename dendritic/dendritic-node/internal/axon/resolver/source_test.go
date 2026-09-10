package resolver

import (
	"os"
	"testing"
)

// sourceOf reads a file in this package, for tests that assert on the source
// rather than on behaviour -- the no-DNS-fallback rule is a property of what the
// code MAY do, which no runtime test can establish.
func sourceOf(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
