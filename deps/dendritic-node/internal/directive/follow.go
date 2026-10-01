package directive

import (
	"net/url"
	"strings"
)

// Following a move: rewriting the URLs that pointed at the old origin.
//
// Adopting a directive and then restarting achieves nothing on its own -- the
// config file still names the old domain in every origin-derived URL, so the
// node comes back up and talks to exactly the host that moved. The directive
// has to be APPLIED to those URLs on the way in.
//
// WHY THIS IS NOT "REPLACE THE DOMAIN EVERYWHERE"
// A node's config can legitimately point at hosts that are nothing to do with
// the origin: a self-hosted registration endpoint, a mirror, a test instance.
// Rewriting every URL because one of them moved would silently redirect an
// operator's deliberate choice to a host they never named. So a URL is only
// followed when it currently points at an origin this node actually believes
// in -- the one it was installed with, or one it has previously adopted.

// RewriteOrigin returns rawURL with its host replaced by newDomain, but only if
// it currently points at one of knownOrigins. The second return says whether it
// changed.
//
// The port is deliberately dropped along with the host: a directive naming a
// domain is naming a service, and carrying ":8443" from the old origin to a new
// one that does not listen there produces a node that fails to connect for a
// reason nobody would look for. A move that needs a port says so in
// origin_address.
func RewriteOrigin(rawURL string, knownOrigins []string, newDomain string) (string, bool) {
	newDomain = strings.TrimSpace(strings.ToLower(newDomain))
	if rawURL == "" || newDomain == "" {
		return rawURL, false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL, false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == newDomain {
		return rawURL, false
	}
	if !matchesAny(host, knownOrigins) {
		// Not an origin URL. Left exactly as the operator wrote it.
		return rawURL, false
	}
	parsed.Host = newDomain
	return parsed.String(), true
}

func matchesAny(host string, candidates []string) bool {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(strings.ToLower(candidate))
		if candidate == "" {
			continue
		}
		// A bare domain or a full URL are both accepted, because the caller is
		// assembling this list from config values of both shapes and a silent
		// non-match here means a node quietly fails to follow a move.
		if parsed, err := url.Parse(candidate); err == nil && parsed.Host != "" {
			candidate = strings.ToLower(parsed.Hostname())
		}
		if host == candidate {
			return true
		}
	}
	return false
}

// HostOf extracts the hostname from a URL or returns a bare domain unchanged.
func HostOf(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		return strings.ToLower(parsed.Hostname())
	}
	return value
}

// Follow describes one URL a directive would change. Returned rather than
// applied so the caller can log it, or show it, before anything moves.
type Follow struct {
	What string // which setting, in words an operator recognises
	From string
	To   string
}

// Plan works out every URL that would change if held were followed.
//
// Separate from applying it because the first real use of this feature will be
// during an incident, and "here is what would change" is the difference between
// an operator who can check the move and one who finds out afterwards. The
// admin rehearsal and the node's own startup log both read from this.
func Plan(held *Directive, knownOrigins []string, urls map[string]string) []Follow {
	if held == nil || held.Kind != KindMove || held.OriginDomain == "" {
		return nil
	}
	var plan []Follow
	for what, current := range urls {
		if updated, changed := RewriteOrigin(current, knownOrigins, held.OriginDomain); changed {
			plan = append(plan, Follow{What: what, From: current, To: updated})
		}
	}
	return plan
}

// KnownOrigins is every host this node has ever been told is the origin: the
// one it was installed with, plus every domain it has adopted since.
//
// The install-time value has to stay in the set. A node that dropped it after
// one move could never follow a directive that moved the network BACK, which is
// the ordinary outcome of a registrar dispute being resolved.
func KnownOrigins(installed string, adopted []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range append([]string{installed}, adopted...) {
		host := HostOf(value)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}
