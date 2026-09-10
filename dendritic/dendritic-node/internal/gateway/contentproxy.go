package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ContentProxy serves site content under the GATEWAY's own hostname.
//
// WHY THIS EXISTS
// ---------------
// The SNI frontend forwards syndichan.org straight to the origin without
// decrypting it. That is safe, and it is also unmeasurable: the reader's TLS
// session ends at the origin, so every response says it came from the origin no
// matter whose machine carried it. A volunteer cannot be credited for honest
// service and cannot be caught at dishonest service, because nothing a reader
// can see distinguishes one gateway from another — or from none.
//
// This handler is the opposite trade. It terminates TLS under
// gw-<hash>.syndichan.org, fetches the object from the origin, and serves it
// under its OWN name and its OWN certificate. That means it *can* alter the
// bytes — which is the point. The origin signs content (X-Syndichan-Signature),
// so a reader can check what they were handed, and an alteration is now a thing
// that can be detected and attributed rather than a thing nobody can express.
//
// The volunteer never holds syndichan.org's private key. It holds a certificate
// for a name that is visibly its own, which is what lets a reader tell which
// party is answering.
//
// WHAT IT REFUSES TO CARRY, AND WHY THAT IS MOST OF THE DESIGN
// ------------------------------------------------------------
// An untrusted machine handling arbitrary site traffic would be a credential
// harvester with extra steps. Every rule below exists to keep the gateway
// confined to public, anonymous, verifiable reads:
//
//   - GET and HEAD only. A gateway must never carry a login, a post, or a
//     payment. Writes are not idempotent, not signed, and not re-checkable, so a
//     forged one could never be detected after the fact.
//   - Cookies are stripped in BOTH directions. Not forwarded, so a reader's
//     session is never exposed to a volunteer; not returned, so a gateway cannot
//     plant a session of its own choosing in a reader's browser. This alone
//     turns the proxy into an anonymous view, which is the only view worth
//     serving from a machine nobody vouches for.
//   - Authorization and similar credential headers are dropped for the same
//     reason.
//   - A deny list for paths that must never be anonymous anyway. Redundant
//     given no cookies travel — admin would simply redirect to a login — but
//     defence that costs nothing should not be omitted because another layer
//     currently happens to hold.
//   - Redirects are returned, never followed. Following one would let a
//     response choose the gateway's next destination.
type ContentProxy struct {
	// Origin is the scheme://host the gateway fetches from.
	Origin *url.URL
	// ServerName is the TLS name to validate the origin against. The origin is
	// reached by address, so the certificate check is what makes this a
	// connection to syndichan.org rather than to whoever holds that address.
	ServerName string
	// NodeID is this gateway's peer ID, announced on every response it serves.
	NodeID     string
	MaxBytes   int64
	client     *http.Client
	deniedPath []string

	// Snapshot and Health turn this from a proxy into a gateway that survives
	// the origin. Both nil by default: an operator who only wants to donate
	// transport gets exactly that.
	Snapshot *SnapshotCache
	Health   *OriginHealth
	// Offload serves publisher-approved routes from the snapshot even while the
	// origin is healthy, which is what turns this from an emergency cache into
	// a way to take read traffic off the origin entirely.
	Offload bool
}

// Paths a gateway has no business carrying even anonymously.
var defaultDeniedPrefixes = []string{
	"/admin", "/api/v1/bot", "/api/v1/admin", "/login", "/logout",
	"/register", "/profile", "/settings", "/stripe", "/webhook",
	"/slip", "/mod", "/report",
}

// Request headers that must never reach a volunteer's machine.
var strippedRequestHeaders = []string{
	"Cookie", "Authorization", "Proxy-Authorization", "X-Csrf-Token",
	"X-Api-Key", "X-Bot-Token",
}

// Response headers a gateway must not be able to set on the origin's behalf.
var strippedResponseHeaders = []string{
	"Set-Cookie", "Set-Cookie2", "Strict-Transport-Security",
}

func NewContentProxy(origin *url.URL, serverName, nodeID string, originAddress string) *ContentProxy {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if originAddress != "" {
		// Pin the origin to a literal address while still validating its
		// certificate by name. DNS for syndichan.org points at gateways as well
		// as at the origin, so resolving it here could send a gateway's fetch to
		// another gateway — a loop, and a way for one volunteer's answer to be
		// laundered through another's identity.
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, originAddress)
		}
	} else {
		transport.DialContext = dialer.DialContext
	}
	return &ContentProxy{
		Origin: origin, ServerName: serverName, NodeID: nodeID,
		MaxBytes:   8 << 20,
		deniedPath: defaultDeniedPrefixes,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *ContentProxy) denied(path string) bool {
	lowered := strings.ToLower(path)
	for _, prefix := range p.deniedPath {
		if lowered == prefix || strings.HasPrefix(lowered, prefix+"/") {
			return true
		}
	}
	return false
}

func (p *ContentProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// 405 rather than a silent proxy: a reader whose post vanished into a
		// volunteer's machine would have no way to tell that is what happened.
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "this gateway serves public reads only", http.StatusMethodNotAllowed)
		return
	}
	if p.denied(r.URL.Path) {
		http.Error(w, "not served by a gateway", http.StatusForbidden)
		return
	}

	// Already known to be down: go straight to the snapshot rather than making
	// the reader wait out a timeout first. Every request that still probes a
	// dead origin is a reader watching a spinner for no information.
	if p.Health != nil && p.Health.Emergency() {
		if p.serveSnapshot(w, r) {
			return
		}
	}

	// ORIGIN OFFLOADING. A route the publisher marked offloadable is one that
	// has rendered identically for several builds AND lost nothing to the
	// read-only rewrite — so the cached bytes ARE the origin's bytes, and
	// serving them costs the reader neither freshness nor a capability.
	//
	// This is the only path that serves cache while the origin is healthy, and
	// it is off unless the operator turned it on. The default stays
	// origin-first, because a gateway quietly deciding to answer from an
	// hour-old copy is a behaviour nobody asked for.
	if p.Offload && p.Snapshot != nil && p.Snapshot.Offloadable(r.URL.Path) {
		if p.serveOffload(w, r) {
			return
		}
	}

	target := *p.Origin
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	outbound, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for name, values := range r.Header {
		if headerIn(name, strippedRequestHeaders) {
			continue
		}
		for _, value := range values {
			outbound.Header.Add(name, value)
		}
	}
	outbound.Host = p.ServerName
	// The origin must be able to tell a gateway fetch from a reader, both for
	// its own logs and so it never treats one as a visitor.
	outbound.Header.Set("X-Syndichan-Gateway-Fetch", p.NodeID)
	outbound.Header.Del("Accept-Encoding") // let Go negotiate; body must be verifiable

	response, err := p.client.Do(outbound)
	if err != nil {
		if p.Health != nil {
			p.Health.RecordFailure(ClassifyError(err))
		}
		// The origin just failed for this reader; serve them the snapshot now
		// rather than making them wait for the threshold to be reached.
		if p.serveSnapshot(w, r) {
			return
		}
		http.Error(w, "origin unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	if p.Health != nil {
		if kind := ClassifyStatus(response.StatusCode); kind != "" {
			p.Health.RecordFailure(kind)
			if p.serveSnapshot(w, r) {
				return
			}
		} else {
			p.Health.RecordSuccess()
		}
	}

	for name, values := range response.Header {
		if headerIn(name, strippedResponseHeaders) {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	// Announce which gateway answered. The origin sets this to "origin"; a
	// gateway overwrites it with its own identity, which is what makes an audit
	// receipt attributable to a specific key. Set, not added: two values would
	// let a gateway claim to be both itself and the origin.
	w.Header().Set("X-Syndichan-Gateway", p.NodeID)
	w.Header().Set("X-Gateway-Version", "1")

	// Readable cross-origin, so a reader on syndichan.org can fetch the same
	// object here and compare it against the origin's signature. Without this
	// the browser hides the response and a gateway becomes un-auditable by the
	// only party positioned to audit it.
	//
	// Safe precisely because of the rules above: no cookie was forwarded, so
	// this is the anonymous public view and nothing here is authorised by the
	// reader's identity. Credentials are NOT allowed, which is what keeps that
	// true — with them, "*" would let any site read a logged-in view.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "false")
	w.Header().Set("Access-Control-Expose-Headers",
		"X-Syndichan-Version, X-Syndichan-Hash, X-Syndichan-Signature, "+
			"X-Syndichan-Key, X-Syndichan-Gateway, X-Gateway-Version")

	w.WriteHeader(response.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, io.LimitReader(response.Body, p.MaxBytes))
}

func headerIn(name string, list []string) bool {
	canonical := http.CanonicalHeaderKey(name)
	for _, candidate := range list {
		if http.CanonicalHeaderKey(candidate) == canonical {
			return true
		}
	}
	return false
}

// serveSnapshot answers from the held emergency copy. Reports whether it did.
//
// THE LOOKUP GUARD
// ----------------
// A route is only served if the SIGNED manifest names it. That is not merely
// tidiness: without it, a request for a random path becomes a cache miss, a disk
// probe, and in a DHT-backed design a network lookup — so anyone with a loop
// could point this gateway's storage at the network as an amplifier. Unknown
// paths get a flat 404 with no lookup at all.
func (p *ContentProxy) serveSnapshot(w http.ResponseWriter, r *http.Request) bool {
	if p.Snapshot == nil || !p.Snapshot.Enabled() {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	manifest := p.Snapshot.Manifest()
	if manifest == nil || !manifest.Usable(time.Now()) {
		return false
	}
	if !p.Snapshot.HasRoute(r.URL.Path) {
		// Known-unknown: the snapshot exists and does not contain this path.
		// Answering here rather than falling through keeps the guard meaningful.
		p.snapshotHeaders(w, manifest)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, maintenancePage(manifest, "That page is not in the emergency copy."))
		}
		return true
	}
	body, contentType, found := p.Snapshot.Object(r.URL.Path)
	if !found {
		return false
	}

	p.snapshotHeaders(w, manifest)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return true
	}
	_, _ = w.Write(body)
	return true
}

func (p *ContentProxy) snapshotHeaders(w http.ResponseWriter, m *SnapshotManifest) {
	state := m.State(time.Now())
	// Names this as emergency content so the reader's verifier checks it against
	// the snapshot manifest rather than a live object signature it cannot have.
	// The header only SELECTS that path — the manifest signature decides whether
	// the bytes are genuine, so a gateway cannot use it to escape checking.
	w.Header().Set("X-Syndichan-Source", "snapshot")
	w.Header().Set("X-Syndichan-Snapshot", strconv.FormatInt(m.Sequence, 10))
	w.Header().Set("X-Syndichan-Snapshot-Time",
		time.Unix(m.CreatedAt, 0).UTC().Format(time.RFC3339))
	w.Header().Set("X-Syndichan-Cache-State", state)
	w.Header().Set("X-Syndichan-Gateway", p.NodeID)
	// Short: the origin may come back at any moment, and a reader holding an
	// emergency copy for an hour would not notice.
	w.Header().Set("Cache-Control", "public, max-age=120")
	w.Header().Set("Warning", `110 - "Response served from emergency cached snapshot"`)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers",
		"X-Syndichan-Source, X-Syndichan-Snapshot, X-Syndichan-Snapshot-Time, "+
			"X-Syndichan-Cache-State, X-Syndichan-Gateway")
}

// MaintenancePage is served when there is no usable snapshot at all.
//
// Compiled in, and depending on nothing: no stylesheet, no script, no font, no
// DHT, no origin. Everything it could depend on is a thing that is plausibly
// broken at the moment it is needed, and a maintenance page that fails to load
// is indistinguishable from the outage it is trying to explain.
func MaintenancePage() string { return maintenancePage(nil, "") }

func maintenancePage(m *SnapshotManifest, note string) string {
	taken := ""
	if m != nil {
		taken = "<p>The most recent saved copy is from " +
			htmlEscape(time.Unix(m.CreatedAt, 0).UTC().Format("2 January 2006 at 15:04 UTC")) +
			".</p>"
	}
	if note != "" {
		note = "<p>" + htmlEscape(note) + "</p>"
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>syndichan — temporarily unavailable</title></head>` +
		`<body style="background:#111;color:#ddd;font:16px/1.6 system-ui,sans-serif;` +
		`margin:0;padding:3rem 1.5rem;text-align:center">` +
		`<h1 style="font-size:1.4rem;color:#ffb84d">syndichan is temporarily in emergency mode</h1>` +
		`<p>The live service is unavailable and no usable cached copy is held here.</p>` +
		note + taken +
		`<p>No logins, posts, purchases or transfers are being processed.</p>` +
		`<p style="color:#888">Please try again shortly.</p></body></html>`
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;",
		`"`, "&quot;", "'", "&#39;")
	return replacer.Replace(value)
}

// serveOffload answers from the UNTOUCHED variant while the origin is healthy.
//
// Deliberately not serveSnapshot. That one sets emergency headers and a Warning,
// and serves the rewritten copy — correct during an outage and wrong here, where
// nothing is wrong: it would tell every reader the site was broken and hand them
// a page with its search box disabled.
//
// What a reader gets here is the origin's own bytes, so the only difference from
// a live fetch is age — and the publisher only marks a route offloadable once it
// has rendered identically for several builds, which is what makes "old" and
// "current" the same thing.
func (p *ContentProxy) serveOffload(w http.ResponseWriter, r *http.Request) bool {
	body, contentType, found := p.Snapshot.OffloadObject(r.URL.Path)
	if !found {
		return false
	}
	manifest := p.Snapshot.Manifest()
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	// Named honestly. Not "snapshot", because a client verifier must check
	// these against the LIVE object signature they carry — they are the
	// origin's bytes and have one — rather than against the snapshot manifest.
	w.Header().Set("X-Syndichan-Source", "gateway-cache")
	if manifest != nil {
		w.Header().Set("X-Syndichan-Snapshot", strconv.FormatInt(manifest.Sequence, 10))
		w.Header().Set("X-Syndichan-Snapshot-Time",
			time.Unix(manifest.CreatedAt, 0).UTC().Format(time.RFC3339))
	}
	w.Header().Set("X-Syndichan-Gateway", p.NodeID)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return true
	}
	_, _ = w.Write(body)
	return true
}
