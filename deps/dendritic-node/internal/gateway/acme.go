package gateway

import (
	"errors"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// NewACMEManager creates an exact-host ACME policy. A volunteer gateway must
// never answer certificate challenges for arbitrary names supplied by a
// request, even when its listener is reachable for those names.
func NewACMEManager(hostname, email, cacheDirectory string) (*autocert.Manager, error) {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if hostname == "" || strings.ContainsAny(hostname, "* /:@[]") ||
		net.ParseIP(hostname) != nil {
		return nil, errors.New("ACME hostname must be a literal DNS hostname")
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' ||
			label[len(label)-1] == '-' {
			return nil, errors.New("ACME hostname must be a literal DNS hostname")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return nil, errors.New("ACME hostname must be a literal DNS hostname")
			}
		}
	}
	if cacheDirectory == "" {
		return nil, errors.New("ACME cache directory is required")
	}
	if err := os.MkdirAll(cacheDirectory, 0700); err != nil {
		return nil, err
	}
	// Tighten an existing directory as well. Certificate private keys are
	// persisted here and must not inherit a permissive umask from the launcher.
	if err := os.Chmod(cacheDirectory, 0700); err != nil {
		return nil, err
	}
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDirectory),
		HostPolicy: autocert.HostWhitelist(hostname),
		Email:      strings.TrimSpace(email),
	}, nil
}
