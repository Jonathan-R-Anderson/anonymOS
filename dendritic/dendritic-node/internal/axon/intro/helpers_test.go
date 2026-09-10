package intro

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// stripComments removes // lines so a source audit cannot match its own
// justifying prose — the failure mode that made the E-G2 and §87 audits vacuous.
func stripComments(body string) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if regexp.MustCompile(`^\s*//`).MatchString(line) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
