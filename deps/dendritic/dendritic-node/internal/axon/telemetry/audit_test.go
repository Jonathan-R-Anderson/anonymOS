// Package telemetry carries T16.3's audit: what a node may say about itself.
//
// It is a test-only package, like internal/axon/storage. There is nothing to
// build — the property is about what the EXISTING telemetry types are allowed to
// contain, and no runtime test of a working monitor establishes that.
//
// T16.3: "Metrics contain no per-circuit, per-name or per-peer identifier, by
// schema audit."
//
// §23's P16 card names the failure mode precisely: "monitoring that is useful
// precisely because it is deanonymising". The useful field and the dangerous
// field are the same field — which circuit was slow, which name failed to
// resolve, which peer timed out — so this cannot be left to judgement at the
// call site. It has to be a rule about the schema.
//
// WHAT IS ALLOWED. Aggregate counts and this node's own identity: how many
// objects, how many peers, how many placements failed, how long a probe took,
// and who is reporting. A node signs its reports, so its own id is attribution
// rather than surveillance, and removing it would make the reports unverifiable.
//
// WHAT IS NOT. Anything that names a THIRD PARTY or a UNIT OF WORK: a circuit
// id, a resolved name, an object or shard id, another peer's identity, an
// address. Each of those turns a health metric into a record of who did what.
package telemetry

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

// transmitting is the set of packages whose types actually leave the node AS
// TELEMETRY -- health and status a node reports about itself.
//
// Listed rather than discovered, and that is the one manual step here: a struct
// with json tags is not necessarily transmitted, and auditing every one of them
// would flag the config file and the on-disk ledger.
//
// The list cannot be left to go stale on its own. Every package that posts JSON
// must appear in EXACTLY ONE of `transmitting` or `notTelemetry`, and
// TestEveryTransmitterIsAudited FAILS on anything in neither -- so adding a new
// sender forces a decision with a written reason rather than silently landing
// outside the audit.
// An entry is a package, or a single FILE when only part of a package sends.
//
// The file form was added for internal/gateway, which is not a telemetry
// package: it is a gateway implementation that happens to contain one
// telemetry-shaped post. Auditing the whole package pulled in the gateway
// REGISTRY protocol's types -- HostnameReservation, Address, directoryEntry --
// which are things this node RECEIVES or registers about ITSELF, and exempting
// their fields to admit the package would have blunted the audit for exactly
// the names most worth catching. Narrowing the scope is the correct direction;
// widening the allowances is not.
var transmitting = []string{
	"internal/monitor",
	"internal/heartbeat",
	"internal/gateway/validator.go",
}

// notTelemetry is every other package that posts JSON, with why it is not
// subject to T16.3.
//
// A reason per package, not a blanket exemption. The distinction being drawn is
// between REPORTING ON YOURSELF, which is what T16.3 governs and where naming a
// third party is a leak, and PROTOCOL TRAFFIC TO A COUNTERPARTY, where the
// remote end is the party you are talking to and naming it is unavoidable --
// you cannot pay a gateway without addressing it.
//
// Reviewed 2026-08-19. Each entry was read, not assumed.
var notTelemetry = map[string]string{
	"internal/channel": "JSON-RPC to an Ethereum endpoint and mailbox delivery to a " +
		"payment counterparty. Protocol traffic, not a health report; its own " +
		"privacy story is \u00a711's, not T16.3's.",
	"internal/dcs": "the container runtime's local API. Does not leave the machine.",
	"internal/directive": "GET only -- it FETCHES a directive feed and sends " +
		"nothing. Caught here anyway because the detector matches the request " +
		"CONSTRUCTOR rather than the method, deliberately: internal/dcs passes " +
		"its method in a variable, so a method-based filter would miss a real " +
		"sender. Broad detection plus a written classification errs toward " +
		"making someone decide.",
	"internal/ethproof": "JSON-RPC reads against chain providers. Requests carry " +
		"chain state, not observations about peers.",
	"internal/facilitation": "signed PoF declarations -- payouts, registration. " +
		"Attributable BY DESIGN: an economic claim nobody can verify anonymously " +
		"is not a claim.",
	"internal/gateway": "content proxying and this node's own gateway " +
		"registration -- protocol traffic. The ONE telemetry-shaped thing in it, " +
		"validator.go's audit report, is audited separately by file; see " +
		"`transmitting`. Classified here so the rest of the package is not " +
		"dragged into a schema audit built for metrics.",
	"internal/p2p": "storage lease requests and revocations to the coordinator. " +
		"Protocol traffic naming the object being leased, to the party issuing " +
		"the lease.",
}

// Field names that name a third party or a unit of work.
var forbidden = regexp.MustCompile(`(?i)^(` +
	`circuit\w*|circ_?id|` +
	`stream_?id|` +
	`name|domain|hostname|fqdn|zone|` +
	`object_?id|shard_?id|cid|manifest|` +
	`peer_?id|remote_?id|node_?ids|` +
	`addr|address|ip|endpoint|destination|multiaddr|` +
	`key_?hash|namehash` +
	`)$`)

// allowedIn is a PER-PACKAGE allowance: field name -> why it is admissible in
// that package and nowhere else.
//
// Per-package rather than global, because the global `allowed` set below applies
// everywhere and a name that is harmless in one sender is exactly the leak in
// another. Admitting internal/gateway's two fields globally would have exempted
// `gateway` and `object_key` from the audit in monitor and heartbeat too, where
// they would be a genuine third-party identifier.
var allowedIn = map[string]map[string]string{
	"internal/gateway/validator.go": {
		// An entry from the site's OWN published gateway directory, posted back
		// to the site that published it. Not a peer this node observed.
		"Gateway": "an entry from the recipient's own published directory",
		// An entry from the site's OWN spot-check feed, defaulting to "/" --
		// the front page. A public content path, not a name anybody resolved
		// and not a per-user object.
		"ObjectKey": "an entry from the recipient's own spot-check feed",
		// directoryEntry is INBOUND -- the site's own directory, unmarshalled
		// here. A schema audit cannot see direction, so the exemption is
		// written down rather than inferred.
		"Hostname": "an inbound field of the site's own gateway directory",
	},
}

// Names that look dangerous and are not, with the reason each is allowed.
var allowed = map[string]string{
	// The reporting node's OWN id. Reports are signed with it; removing it makes
	// them unverifiable, and it identifies the reporter rather than a subject.
	"NodeID": "the reporting node's own identity, which its signature already binds",
	// A probe target's short key ("gateway", "dht") — a component name, not a
	// name anybody resolved.
	"Key": "a component key such as \"gateway\", not a resolved name",
	// The human label of a probe target, from the site's own target list.
	"Name": "a probe target's label, supplied by the site rather than observed",
	// A probe target's URL, likewise from the site's own list.
	"URL":       "a probe target supplied by the site, not a destination a user chose",
	"ReportURL": "where to post, supplied by the site",
}

// goFilesIn resolves a `transmitting` entry to the files it covers: every
// non-test .go file in a package, or the one file a file-scoped entry names.
func goFilesIn(t *testing.T, entry string) []string {
	t.Helper()
	if strings.HasSuffix(entry, ".go") {
		path := filepath.Join(repoRoot(t), entry)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("transmitting names %s, which is not there: %v", entry, err)
		}
		return []string{path}
	}
	dir := filepath.Join(repoRoot(t), entry)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", entry, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

// pkgOf is the package a `transmitting` entry belongs to.
func pkgOf(entry string) string {
	if strings.HasSuffix(entry, ".go") {
		return filepath.ToSlash(filepath.Dir(entry))
	}
	return entry
}

func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..")
}

// TestT163NoTelemetryFieldNamesAThirdParty is T16.3.
func TestT163NoTelemetryFieldNamesAThirdParty(t *testing.T) {
	fset := token.NewFileSet()
	checked := 0

	for _, pkg := range transmitting {
		for _, path := range goFilesIn(t, pkg) {
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					// Only fields that are SERIALISED. An unexported or
					// untagged field stays inside the process.
					if field.Tag == nil || !strings.Contains(field.Tag.Value, `json:"`) {
						continue
					}
					for _, name := range field.Names {
						checked++
						if !name.IsExported() {
							continue
						}
						if _, ok := allowed[name.Name]; ok {
							continue
						}
						if _, ok := allowedIn[pkg][name.Name]; ok {
							continue
						}
						if forbidden.MatchString(name.Name) {
							t.Errorf("T16.3 violated: %s has a transmitted field %q. "+
								"Metrics may carry aggregate counts and this node's own "+
								"identity; a field naming a third party or a unit of work "+
								"turns monitoring into a record of who did what.",
								path, name.Name)
						}
					}
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no transmitted fields were examined; the audit is looking in the wrong place")
	}
	t.Logf("T16.3: %d transmitted fields checked across %d packages", checked, len(transmitting))
}

// posts matches the ways this tree actually sends a request.
//
// NewRequestWithContext IS THE ONE THAT MATTERED. The first version of this
// detector looked for `http.(Post|NewRequest)(` and nothing else, and this
// codebase builds 28 of its senders with `http.NewRequestWithContext(` -- which
// does not match, because of the `\(`. So the guard below examined ZERO
// packages and passed every run: not warning weakly, warning about nothing.
// TestTheDetectorIsNotVacuous exists so that cannot recur silently.
var posts = regexp.MustCompile(`http\.(Post|PostForm|NewRequest|NewRequestWithContext)\(`)

// TestEveryTransmitterIsAudited stops the list above from going stale.
//
// The audit is only as good as its scope. A new package that posts telemetry and
// is not in `transmitting` is unaudited, and nothing would say so — which is the
// same silent-gap shape as the metrics leak itself.
//
// NOW A FAILURE, NOT A NOTE. It logged its findings and passed, on the reasoning
// that "not everything that posts is telemetry -- a payment client posts too",
// so the list would be reviewed rather than grown reflexively. That reasoning is
// right and the conclusion did not follow: the fix for "this needs judgement" is
// to REQUIRE the judgement, not to skip it. Every posting package must be
// classified into `transmitting` or `notTelemetry`; anything in neither fails
// here, and the failure names the two lists.
func TestEveryTransmitterIsAudited(t *testing.T) {
	root := filepath.Join(repoRoot(t), "internal")

	var unaudited []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		body := string(src)
		// Posts somewhere AND declares a json-tagged struct: that is the shape
		// of a telemetry sender.
		if !posts.MatchString(body) || !strings.Contains(body, `json:"`) {
			return nil
		}
		rel := filepath.ToSlash(filepath.Dir(path))
		i := strings.Index(rel, "internal/")
		if i < 0 {
			return nil
		}
		rel = rel[i:]
		for _, known := range transmitting {
			if rel == pkgOf(known) {
				return nil
			}
		}
		if _, classified := notTelemetry[rel]; classified {
			return nil
		}
		unaudited = append(unaudited, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	seen := map[string]bool{}
	var uniq []string
	for _, u := range unaudited {
		if !seen[u] {
			seen[u] = true
			uniq = append(uniq, u)
		}
	}
	if len(uniq) > 0 {
		t.Errorf("T16.3: %d package(s) POST json and are classified neither way. "+
			"Read each one and either add it to `transmitting` (it reports on "+
			"this node and must obey the field rules) or to `notTelemetry` WITH "+
			"A REASON (it is protocol traffic to a counterparty). Leaving it "+
			"unclassified means it is unaudited and nothing says so:\n  %s",
			len(uniq), strings.Join(uniq, "\n  "))
	}

	// A stale entry is the other half of the same problem: a package listed as
	// exempt that no longer posts anything leaves a reason nobody will re-read.
	for pkg := range notTelemetry {
		if _, err := os.Stat(filepath.Join(repoRoot(t), pkg)); err != nil {
			t.Errorf("notTelemetry names %s, which is not there any more", pkg)
		}
	}
}

// TestTheDetectorIsNotVacuous is the guard on the guard.
//
// TestEveryTransmitterIsAudited can only be as good as `posts`, and for as long
// as that regex missed NewRequestWithContext it examined nothing and passed --
// a green check standing for an audit that never ran, which is worse than no
// check at all because it reads as coverage.
//
// So: the detector must find the packages we already KNOW send telemetry. If it
// cannot see monitor and heartbeat, it cannot see whatever replaces them.
func TestTheDetectorIsNotVacuous(t *testing.T) {
	for _, pkg := range transmitting {
		found := false
		for _, path := range goFilesIn(t, pkg) {
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				continue
			}
			if posts.Match(src) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the sender detector cannot see %s, which is a known "+
				"telemetry sender. Whatever idiom it uses now is invisible to "+
				"TestEveryTransmitterIsAudited, so that test is passing "+
				"vacuously — widen `posts` rather than trusting the green.", pkg)
		}
	}
}

// TestTransmittedPayloadsAreStructsNotMaps closes the schema audit's other
// blind spot.
//
// T16.3's field check parses STRUCT FIELD NAMES. A payload assembled as
// `map[string]any{"peer_id": ...}` has no field names to parse, so it passes
// the audit by being invisible to it -- and internal/gateway already builds one
// that way, carrying another node's id and an object key.
//
// The rule is therefore narrow and enforceable: inside a package that IS
// audited, a request body may not be marshalled from a map literal. Elsewhere
// it is a judgement call and stays one.
func TestTransmittedPayloadsAreStructsNotMaps(t *testing.T) {
	marshalsMap := regexp.MustCompile(`json\.Marshal\(\s*map\[string\]`)
	for _, pkg := range transmitting {
		for _, path := range goFilesIn(t, pkg) {
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				continue
			}
			if marshalsMap.Match(src) {
				t.Errorf("%s marshals a map literal. The T16.3 audit reads "+
					"struct field names, so a map payload is exempt by being "+
					"unreadable — use a tagged struct so the schema rule applies.",
					path)
			}
		}
	}
}

// TestFreeTextFieldsAreBounded covers the field a schema audit cannot see into.
//
// `Detail string` is the escape hatch: it passes every name check and can carry
// anything the code decides to put in it. A schema rule cannot police its
// CONTENTS, so the rule is about its SIZE — a detail long enough to hold a
// multiaddr or a manifest CID is long enough to be worth reviewing.
func TestFreeTextFieldsAreBounded(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "monitor", "monitor.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, "Detail") {
		t.Skip("no Detail field to bound")
	}
	// Now an assertion, not a note. The first run of this audit reported Detail
	// as unbounded free text; monitor.sanitiseDetail was added in response, so
	// the property is real and must stay.
	if !strings.Contains(body, "sanitiseDetail(") {
		t.Error("T16.3: monitor's Detail is assigned without sanitiseDetail. Go's " +
			"HTTP errors carry the RESOLVED ADDRESS of the target -- " +
			`Get "https://x": dial tcp 203.0.113.9:443: connection refused` +
			" -- and a schema audit checks field names, so it cannot see this.")
	}
	for _, want := range []string{"maxDetail", "ipInError"} {
		if !strings.Contains(body, want) {
			t.Errorf("T16.3: monitor no longer bounds Detail (%s is gone)", want)
		}
	}
	// Every assignment must go through it, not just the first one.
	for i, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "result.Detail =") {
			continue
		}
		if !strings.Contains(trimmed, "sanitiseDetail(") {
			t.Errorf("monitor.go:%d assigns Detail without sanitising:\n\t%s", i+1, trimmed)
		}
	}
}
