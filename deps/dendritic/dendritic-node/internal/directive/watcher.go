package directive

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StoreFile is where the last verified directive is kept, under the data dir.
const StoreFile = "network-directive.json"

// Store holds the directive this node has accepted, across restarts.
//
// Persistence is not a convenience here, it is the security property. The
// sequence rule only means anything if the node REMEMBERS the highest one it
// has seen -- a node that forgets on restart would accept a replayed directive
// from a year ago, which is the exact attack the sequence exists to stop.
type Store struct {
	path string

	mu      sync.RWMutex
	held    *Directive
	domains []string
}

type storedState struct {
	Directive *Directive `json:"directive"`
	Signature string     `json:"signature"`
	Signer    string     `json:"signer"`
	AdoptedAt int64      `json:"adopted_at"`
	// Domains is every origin this node has adopted, oldest first.
	//
	// Kept as a list rather than just the current one so a later directive can
	// move the network BACK -- the ordinary outcome of a registrar dispute
	// being resolved. With only the current domain remembered, a URL that had
	// already been rewritten away from the original would no longer match
	// anything and would silently stop following.
	Domains []string `json:"domains,omitempty"`
}

func OpenStore(dataDir string) (*Store, error) {
	s := &Store{path: filepath.Join(dataDir, StoreFile)}
	body, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var state storedState
	if err := json.Unmarshal(body, &state); err != nil {
		// A corrupt store is NOT treated as "nothing held". Starting from
		// scratch would silently drop the sequence floor and re-open the replay
		// window; refusing to start is the safe direction for a file that
		// should only ever have been written by this node.
		return nil, fmt.Errorf("%s is unreadable (%v) -- refusing to start "+
			"without the sequence floor it holds", s.path, err)
	}
	s.held = state.Directive
	s.domains = state.Domains
	return s, nil
}

// Domains is every origin this node has adopted, oldest first.
func (s *Store) Domains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.domains...)
}

func (s *Store) Held() *Directive {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.held
}

func (s *Store) Adopt(d *Directive, signature, signer string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := CheckAcceptable(d, s.held); err != nil {
		return err
	}
	domains := s.domains
	if d.Kind == KindMove && d.OriginDomain != "" {
		domains = appendUnique(domains, d.OriginDomain)
	}
	body, err := json.MarshalIndent(storedState{
		Directive: d, Signature: signature, Signer: signer, AdoptedAt: now,
		Domains: domains,
	}, "", "  ")
	if err != nil {
		return err
	}
	// Written to a temp file and renamed: a half-written store is a store that
	// cannot be read, and OpenStore refuses to start on one. An interrupted
	// power cycle must not brick the node.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.held = d
	s.domains = domains
	return nil
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(append([]string(nil), list...), value)
}

// Logger is the subset of *log.Logger this package needs.
type Logger interface {
	Printf(format string, v ...interface{})
}

// Watcher polls for a newer directive and adopts it when it verifies.
type Watcher struct {
	// Wallet is the address pinned in THIS node's config. Never fetched.
	Wallet string
	// Sources are URLs serving the document. More than one on purpose: the
	// source that depends on the current domain is exactly the one that fails
	// in the situation a directive exists for.
	Sources []string
	Store   *Store
	Client  *http.Client
	Log     Logger

	// Credentials for this node's OWN object store, used only for loopback
	// sources. The object-store copy is the one a node can read without the
	// origin, its domain or its certificate — and the endpoint requires SigV4,
	// so an unsigned GET is a 403 and that path silently does not exist.
	Credentials Credentials

	Interval time.Duration
	Now      func() int64

	// OnAdopt is called with a directive that verified AND is effective. This
	// is where the node changes what it points at.
	OnAdopt func(*Directive)
}

func (w *Watcher) now() int64 {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now().Unix()
}

func (w *Watcher) logf(format string, v ...interface{}) {
	if w.Log != nil {
		w.Log.Printf(format, v...)
	}
}

// Run polls until the context ends.
func (w *Watcher) Run(ctx context.Context) {
	if w.Wallet == "" {
		// Deliberately loud and then inert. A node with no pinned wallet has no
		// way to tell a real directive from anyone else's, and quietly polling
		// anyway would mean the first plausible document wins.
		w.logf("network directive: no wallet is pinned in this node's config, " +
			"so directives cannot be verified and will not be followed")
		return
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	w.Poll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Poll(ctx)
		}
	}
}

// Poll tries every source once and adopts the first directive that verifies.
func (w *Watcher) Poll(ctx context.Context) {
	for _, source := range w.Sources {
		doc, err := w.fetch(ctx, source)
		if err != nil {
			w.logf("network directive: %s unavailable (%v)", source, err)
			continue
		}
		if doc.Directive == nil {
			continue
		}
		held := w.Store.Held()
		if held != nil && doc.Directive.Sequence <= held.Sequence {
			continue // nothing new here; not worth a log line every 15 minutes
		}

		verified, err := Verify(doc, w.Wallet, held)
		if err != nil {
			// Logged at every source, because a directive that fails to verify
			// is either a mistake worth fixing or an attempt worth seeing.
			w.logf("network directive: REFUSED from %s: %v", source, err)
			continue
		}

		now := w.now()
		if !verified.Effective(now) {
			w.logf("network directive: sequence %d verified from %s but is not "+
				"effective for another %ds -- this is the window in which an "+
				"operator can freeze a directive they did not issue",
				verified.Sequence, source, verified.NotBefore-now)
			continue
		}

		if err := w.Store.Adopt(verified, doc.Signature, doc.Signer, now); err != nil {
			w.logf("network directive: could not adopt sequence %d: %v",
				verified.Sequence, err)
			continue
		}
		if verified.Emergency {
			// An emergency directive skipped the delay. The only thing bought
			// in exchange is that it cannot happen quietly.
			w.logf("NETWORK DIRECTIVE (EMERGENCY): adopted sequence %d, kind=%s, "+
				"domain=%s -- this took effect immediately with no delay",
				verified.Sequence, verified.Kind, verified.OriginDomain)
		} else {
			w.logf("network directive: adopted sequence %d, kind=%s, domain=%s",
				verified.Sequence, verified.Kind, verified.OriginDomain)
		}
		if w.OnAdopt != nil {
			w.OnAdopt(verified)
		}
		return
	}
}

// isLoopback reports whether a URL points at this machine.
//
// Loopback sources are the node's OWN object-store endpoint, which is the one
// place a directive can be read without the origin, its domain or its
// certificate — all of which a directive may be announcing the loss of.
func isLoopback(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// flipScheme returns the same URL with http<->https swapped.
//
// The node's S3 endpoint serves TLS only when the operator has configured a
// certificate, so its scheme is not knowable when the config is generated at
// download time. Guessing wrong would mean the node silently never reads the
// one source that survives losing the domain — a failure that looks like
// nothing at all until a move happens and it does not follow.
func flipScheme(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "https"
	case "https":
		parsed.Scheme = "http"
	default:
		return ""
	}
	return parsed.String()
}

func (w *Watcher) fetch(ctx context.Context, source string) (*Document, error) {
	doc, err := w.fetchOnce(ctx, source)
	if err == nil || !isLoopback(source) {
		return doc, err
	}
	alternate := flipScheme(source)
	if alternate == "" {
		return doc, err
	}
	if retried, retryErr := w.fetchOnce(ctx, alternate); retryErr == nil {
		w.logf("network directive: %s answered on %s instead", source, alternate)
		return retried, nil
	}
	return doc, err
}

func (w *Watcher) fetchOnce(ctx context.Context, source string) (*Document, error) {
	client := w.Client
	if client == nil {
		timeout := 20 * time.Second
		if isLoopback(source) {
			// Certificate verification is skipped for the node's OWN endpoint,
			// and only for it. The cert there is self-signed by this machine,
			// so verifying it establishes nothing — and nothing is being
			// trusted from the transport anyway: the directive's authority is
			// the wallet signature, which is checked whatever carried it.
			client = &http.Client{
				Timeout: timeout,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		} else {
			client = &http.Client{Timeout: timeout}
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	if isLoopback(source) {
		// Signed with this node's own credentials, for a service on its own
		// loopback interface. Nothing is granted to anyone by this: it is the
		// node proving to itself that it is itself.
		SignGet(request, w.Credentials, time.Now())
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", response.StatusCode)
	}
	// Capped: this document is a few hundred bytes, and an unbounded read from
	// a host that may not be ours any more is a memory exhaustion primitive.
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	return ParseDocument(body)
}

// OriginBase is the URL this node should treat as the origin, given what it
// holds. Falls back to the configured default when nothing has been adopted.
func OriginBase(held *Directive, configured string) string {
	if held != nil && held.Kind == KindMove && held.OriginDomain != "" {
		return "https://" + held.OriginDomain
	}
	return configured
}
