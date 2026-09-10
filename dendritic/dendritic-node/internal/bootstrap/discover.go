package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DocumentPath is where every gateway serves the bootstrap document.
const DocumentPath = "/.well-known/syndichan/storage-node.json"

const (
	fetchTimeout = 15 * time.Second
	// Enough sources to make agreement meaningful, few enough that a joining
	// node is not hammering every gateway in the network on every refresh.
	maxSources = 5
)

// Resolver is the DNS surface used, so tests do not need real records.
type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// Logger is the subset of *log.Logger this package needs.
type Logger interface {
	Printf(format string, v ...interface{})
}

// Discover turns an SRV name into bootstrap URLs.
//
// SRV rather than A records on an aggregate name, because a node needs the
// gateway's HOSTNAME to complete TLS: gateways hold certificates for
// gw-<id>.<domain>, so connecting to a bare address would fail verification and
// the only ways out would be skipping it — which hands the document to anyone
// on the path — or a certificate per shared name, which nobody would maintain.
//
// Priority and weight are honoured in the ordinary way, so the controller can
// steer joining nodes without them needing to know anything about it.
func Discover(ctx context.Context, resolver Resolver, srvName string) []string {
	srvName = strings.TrimSpace(srvName)
	if srvName == "" {
		return nil
	}
	service, proto, domain := splitSRV(srvName)
	if domain == "" {
		return nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	_, records, err := resolver.LookupSRV(ctx, service, proto, domain)
	if err != nil || len(records) == 0 {
		return nil
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Priority != records[j].Priority {
			return records[i].Priority < records[j].Priority
		}
		if records[i].Weight != records[j].Weight {
			return records[i].Weight > records[j].Weight
		}
		return records[i].Target < records[j].Target
	})

	var urls []string
	for _, record := range records {
		host := strings.TrimSuffix(record.Target, ".")
		if host == "" {
			continue
		}
		if record.Port != 0 && record.Port != 443 {
			host = fmt.Sprintf("%s:%d", host, record.Port)
		}
		urls = append(urls, "https://"+host+DocumentPath)
		if len(urls) >= maxSources {
			break
		}
	}
	return urls
}

// splitSRV pulls "_service._proto.domain" apart. Go's LookupSRV wants the three
// pieces separately and rebuilds the name itself.
func splitSRV(name string) (string, string, string) {
	parts := strings.SplitN(strings.TrimPrefix(name, "_"), ".", 3)
	if len(parts) != 3 {
		return "", "", ""
	}
	return parts[0], strings.TrimPrefix(parts[1], "_"), parts[2]
}

// Sources is every URL to try, discovery first and configured URLs after.
func Sources(ctx context.Context, resolver Resolver, cfg Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, url := range append(Discover(ctx, resolver, cfg.SRVName), cfg.URLs...) {
		url = strings.TrimSpace(url)
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		out = append(out, url)
	}
	return out
}

// Fetch asks every source and applies the three rules.
//
// Every source is asked even once a good answer is in hand — with a pinned key
// the extra fetches are what turn a hostile gateway from "ignored" into
// "noticed", and that is the only way anybody finds out.
func Fetch(ctx context.Context, client *http.Client, resolver Resolver,
	cfg Config, log Logger, now time.Time) (*Result, error) {

	sources := Sources(ctx, resolver, cfg)
	if len(sources) == 0 {
		return nil, ErrNoSources
	}
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}

	result := &Result{}
	type good struct {
		doc         *Document
		rawExpires  string
		source      string
		fingerprint string
		verified    bool
	}
	var answers []good

	for _, source := range sources {
		doc, rawExpires, err := fetchOne(ctx, client, source)
		if err != nil {
			result.Unreachable = append(result.Unreachable, source)
			continue
		}
		if !doc.ExpiresAt.IsZero() && now.After(doc.ExpiresAt) {
			// Expiry is signed, so a stale document is not a forgery — but it
			// is a gateway serving something it should have refreshed, and
			// acting on it would dial peers that may be long gone.
			logf(log, "bootstrap: %s served a document that expired %s ago",
				source, now.Sub(doc.ExpiresAt).Round(time.Second))
			result.Disagreed = append(result.Disagreed, source)
			continue
		}
		verified := false
		if cfg.CoordinatorKey != "" {
			if err := Verify(doc, rawExpires, cfg.CoordinatorKey); err != nil {
				// With a key pinned this is unambiguous: whatever this gateway
				// served, the coordinator did not sign it. Named, not merely
				// skipped.
				logf(log, "bootstrap: REFUSED %s: %v", source, err)
				result.Disagreed = append(result.Disagreed, source)
				continue
			}
			verified = true
		}
		answers = append(answers, good{doc, rawExpires, source,
			Fingerprint(doc), verified})
	}

	if len(answers) == 0 {
		return result, ErrNoSources
	}

	// Group by what they actually claim, not by raw bytes: each origin call
	// stamps a fresh expiry and signature, so two gateways proxying the same
	// origin seconds apart differ byte-for-byte while saying the same thing.
	counts := map[string]int{}
	for _, answer := range answers {
		counts[answer.fingerprint]++
	}

	best := answers[0]
	for _, answer := range answers {
		// A signature-verified answer wins outright; among equals, the one
		// more sources agree with.
		if (answer.verified && !best.verified) ||
			(answer.verified == best.verified &&
				counts[answer.fingerprint] > counts[best.fingerprint]) {
			best = answer
		}
	}

	for _, answer := range answers {
		if answer.fingerprint != best.fingerprint {
			result.Disagreed = append(result.Disagreed, answer.source)
		}
	}

	result.Document = best.doc
	result.Source = best.source
	result.Verified = best.verified
	result.Agreed = counts[best.fingerprint]

	if !best.verified {
		// No pinned key, so nothing here is proven — only corroborated.
		// Requiring several independent sources to say the same thing is
		// strictly better than believing whoever answered first, which is the
		// behaviour this replaces, and it is still weaker than a signature.
		required := cfg.MinimumAgreement
		if required <= 0 {
			required = DefaultAgreement
		}
		if result.Agreed < required {
			logf(log, "bootstrap: %d source(s) agreed, %d required, and no "+
				"coordinator key is pinned in this node's config — refusing to "+
				"act on an unverifiable document", result.Agreed, required)
			return result, ErrNoAgreement
		}
		logf(log, "bootstrap: accepted on agreement across %d sources; NO "+
			"coordinator key is pinned, so this is corroborated rather than "+
			"verified. Pin bootstrap.coordinator_key to make it verified.",
			result.Agreed)
	}

	if len(result.Disagreed) > 0 {
		// Evidence, not noise. With a pinned key a disagreeing gateway served
		// something the coordinator did not sign, which is attributable
		// misbehaviour rather than a difference of opinion.
		logf(log, "bootstrap: %d source(s) disagreed with the accepted "+
			"document: %s", len(result.Disagreed),
			strings.Join(result.Disagreed, ", "))
	}
	return result, nil
}

func fetchOne(ctx context.Context, client *http.Client, source string) (*Document, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, "", err
	}
	return Parse(body)
}

func logf(log Logger, format string, v ...interface{}) {
	if log != nil {
		log.Printf(format, v...)
	}
}
