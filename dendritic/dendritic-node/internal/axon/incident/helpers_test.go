package incident

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/bootstrap"
)

func repoRoot() string { return filepath.Join("..", "..", "..") }

func readProcedure(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot(), "INCIDENT-RESPONSE.md"))
	if err != nil {
		t.Fatalf("E16.4 requires a PUBLISHED procedure: %v", err)
	}
	return string(body)
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

func loadBootstrapCache(dir string) (*bootstrap.Cache, error) {
	return bootstrap.LoadCache(dir, time.Now())
}
