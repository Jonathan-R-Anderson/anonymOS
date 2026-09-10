package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Validator re-fetches published objects from gateways and reports what it was
// served, signed with this node's persistent identity.
//
// WHY A NODE AND NOT A SCRIPT
// ---------------------------
// Readers already audit (see the browser verifier), and their reports are the
// broadest evidence available. What they cannot supply is WEIGHT: a browser
// generates a keypair for free, so a thousand reader reports may be one person.
// A validator signs with the key it registered under, which is attributable to
// an operator who can be found again and who has standing to lose. That is the
// only reason validator receipts are eligible for quorum and reader receipts
// are not.
//
// WHAT THIS DOES NOT ESTABLISH
// ----------------------------
// Running five of these does not make five independent validators. The origin
// weighs receipts by distinct OPERATOR and NETWORK, not by count, precisely so
// that one person running a fleet cannot manufacture agreement. This program
// therefore has no way to make its own reports count for more, which is
// deliberate: an honest validator and a dishonest one should have exactly the
// same options here.
type Validator struct {
	Signer Signer
	// Origin is the site that publishes the signing key and the directories.
	Origin string
	// Interval between rounds. Each round audits one gateway.
	Interval time.Duration
	// SampleSize caps how many objects are checked per round, so a validator is
	// a background contributor rather than a load generator.
	SampleSize int
	Logger     *log.Logger
	client     *http.Client
	random     *rand.Rand
}

type directoryEntry struct {
	NodeID   string `json:"node_id"`
	Hostname string `json:"hostname"`
	Healthy  bool   `json:"healthy"`
}

type spotCheck struct {
	ObjectKey string `json:"object_key"`
	Version   int64  `json:"version"`
}

type originKey struct {
	PublicKey string `json:"public_key"`
	Signing   bool   `json:"signing"`
}

// NewValidator builds a validator with conservative defaults.
func NewValidator(signer Signer, origin string, logger *log.Logger, seed int64) *Validator {
	return &Validator{
		Signer: signer, Origin: strings.TrimRight(origin, "/"),
		Interval: 10 * time.Minute, SampleSize: 3, Logger: logger,
		client: &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// A redirect would let a gateway send the audit somewhere it
				// controls and have the answer counted as its own.
				return http.ErrUseLastResponse
			}},
		random: rand.New(rand.NewSource(seed)),
	}
}

// Run audits until the context is cancelled.
func (v *Validator) Run(ctx context.Context) {
	if v.Interval <= 0 {
		v.Interval = 10 * time.Minute
	}
	ticker := time.NewTicker(v.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := v.round(ctx); err != nil && v.Logger != nil {
				v.Logger.Printf("validator round failed: %v", err)
			}
		}
	}
}

func (v *Validator) round(ctx context.Context) error {
	key, err := v.originPublicKey(ctx)
	if err != nil {
		return err
	}
	gateways, err := v.directory(ctx)
	if err != nil {
		return err
	}
	if len(gateways) == 0 {
		return nil
	}
	// Never audit itself. A gateway confirming its own honesty is not evidence,
	// and letting it try would put a self-signed "pass" into the same pool the
	// quorum draws from.
	candidates := make([]directoryEntry, 0, len(gateways))
	for _, entry := range gateways {
		if entry.Healthy && entry.NodeID != v.Signer.ID() {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	target := candidates[v.random.Intn(len(candidates))]

	objects, err := v.objects(ctx)
	if err != nil || len(objects) == 0 {
		// No spot-check feed yet is not an error: audit the front page, which
		// every deployment has.
		objects = []spotCheck{{ObjectKey: "/"}}
	}
	v.random.Shuffle(len(objects), func(i, j int) {
		objects[i], objects[j] = objects[j], objects[i]
	})
	if len(objects) > v.SampleSize {
		objects = objects[:v.SampleSize]
	}
	for _, object := range objects {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		v.audit(ctx, key, target, object)
	}
	return nil
}

// auditReport is the body posted to /api/v1/gateway/audit.
//
// A TAGGED STRUCT RATHER THAN A MAP LITERAL, and the reason is not style.
// T16.3's schema audit (internal/axon/telemetry) reads STRUCT FIELD NAMES, so a
// payload assembled as map[string]any has no field names to read and passes the
// audit by being invisible to it. This one was a map, and a field naming a real
// third party could have been added to it without anything noticing.
//
// The field names and JSON keys are unchanged, and the signature is over
// `message` rather than over this encoding, so the wire format the backend
// parses is identical -- JSON object key order is not significant and no
// signature covers it.
//
// WHAT THIS PAYLOAD DOES AND DOES NOT REVEAL, since it was briefly recorded as a
// privacy cost and that was wrong. `Gateway` is an entry from the site's OWN
// published directory and `ObjectKey` is an entry from the site's OWN
// spot-check feed, defaulting to "/" -- the front page. Both originate at the
// recipient, so posting them back tells it nothing it did not publish, and
// neither is a per-user, per-circuit or per-name identifier of the kind T16.3
// exists to keep out of metrics. It is audited rather than exempted so that
// stays true of whatever is added later.
type auditReport struct {
	Gateway      string `json:"gateway"`
	ObjectKey    string `json:"object_key"`
	Version      int64  `json:"version"`
	ObjectHash   string `json:"object_hash"`
	Result       string `json:"result"`
	LatencyMS    int    `json:"latency_ms"`
	ObserverKind string `json:"observer_kind"`
	ObserverKey  string `json:"observer_key"`
	Signature    string `json:"signature"`
}

// audit fetches one object from one gateway and reports what came back.
func (v *Validator) audit(ctx context.Context, key []byte, gateway directoryEntry,
	object spotCheck) {
	target := "https://" + gateway.Hostname + object.ObjectKey
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return
	}
	started := time.Now()
	response, err := v.client.Do(request)
	if err != nil {
		// Unreachable is an availability fact, and this cannot tell a bad
		// gateway from a bad path between here and it. Reporting it as a
		// content failure would let one flaky link condemn an honest operator.
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return
	}
	latency := int(time.Since(started).Milliseconds())

	version := response.Header.Get("X-Syndichan-Version")
	signature := response.Header.Get("X-Syndichan-Signature")
	served := response.Header.Get("X-Syndichan-Gateway")
	digest := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(digest[:])

	result := "pass"
	switch {
	case version == "" || signature == "":
		// Stripping the headers is not an absence of evidence; it is the
		// evidence. A gateway that will not let itself be checked has said
		// something about itself.
		result = "unsigned"
	case !verifyObject(key, object.ObjectKey, version, bodyHash, signature):
		result = "mismatch"
	case object.Version > 0 && parseVersion(version) < object.Version:
		// Authentic but older than a reader was already served. The one attack
		// a hash cannot see.
		result = "stale"
	}
	// Attribute to the identity the gateway CLAIMS only when it matches the
	// directory. A gateway naming someone else would otherwise file its own
	// misbehaviour under a rival's key.
	subject := gateway.NodeID
	if served != "" && served != gateway.NodeID {
		result, subject = "mismatch", gateway.NodeID
	}
	v.report(ctx, subject, object.ObjectKey, version, bodyHash, result, latency)
}

func verifyObject(key []byte, objectKey, version, bodyHash, signature string) bool {
	raw, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(
		strings.TrimRight(signature, "="))
	if err != nil || len(raw) != 64 || len(key) != 32 {
		return false
	}
	message := []byte("syndichan-object:v1\n" + objectKey + "\n" + version + "\n" + bodyHash)
	return ed25519.Verify(ed25519.PublicKey(key), message, raw)
}

func parseVersion(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

// report signs the observation and submits it. Signing is what separates a
// validator receipt from an anonymous one: the origin can tell which registered
// node said this, and refuses validator standing to any key it does not know.
func (v *Validator) report(ctx context.Context, gateway, objectKey, version,
	bodyHash, result string, latency int) {
	message := strings.Join([]string{
		"syndichan-audit:v1", gateway, objectKey,
		strconv.FormatInt(parseVersion(version), 10), bodyHash, result,
	}, "\n")
	signature, err := v.Signer.Sign([]byte(message))
	if err != nil {
		return
	}
	publicKey, err := v.Signer.PublicKey()
	if err != nil {
		return
	}
	// Signer.PublicKey returns the libp2p protobuf wrapper; send the raw 32
	// bytes, which is the form registration stores and the form a verifier can
	// use without knowing about libp2p at all.
	if len(publicKey) == 36 && string(publicKey[:4]) == "\x08\x01\x12\x20" {
		publicKey = publicKey[4:]
	}
	payload, err := json.Marshal(auditReport{
		Gateway:      gateway,
		ObjectKey:    objectKey,
		Version:      parseVersion(version),
		ObjectHash:   bodyHash,
		Result:       result,
		LatencyMS:    latency,
		ObserverKind: "validator",
		ObserverKey:  base64.StdEncoding.EncodeToString(publicKey),
		Signature:    base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		v.Origin+"/api/v1/gateway/audit", strings.NewReader(string(payload)))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if v.Logger != nil && result != "pass" {
		v.Logger.Printf("validator: %s served %s for %s", shortID(gateway), result, objectKey)
	}
}

func (v *Validator) originPublicKey(ctx context.Context) ([]byte, error) {
	var document originKey
	if err := v.fetchJSON(ctx, "/.well-known/syndichan/origin-key.json", &document); err != nil {
		return nil, err
	}
	if !document.Signing || document.PublicKey == "" {
		return nil, fmt.Errorf("origin is not signing content")
	}
	return base64.StdEncoding.DecodeString(document.PublicKey)
}

func (v *Validator) directory(ctx context.Context) ([]directoryEntry, error) {
	var entries []directoryEntry
	if err := v.fetchJSON(ctx, "/api/v1/gateways", &entries); err == nil {
		return entries, nil
	}
	// Older deployments wrap the list; accept both rather than stop auditing.
	var wrapped struct {
		Gateways []directoryEntry `json:"gateways"`
	}
	if err := v.fetchJSON(ctx, "/api/v1/gateways", &wrapped); err != nil {
		return nil, err
	}
	return wrapped.Gateways, nil
}

func (v *Validator) objects(ctx context.Context) ([]spotCheck, error) {
	var payload struct {
		Objects []spotCheck `json:"objects"`
	}
	if err := v.fetchJSON(ctx, "/api/v1/gateway/spot-checks", &payload); err != nil {
		return nil, err
	}
	return payload.Objects, nil
}

func (v *Validator) fetchJSON(ctx context.Context, path string, into any) error {
	endpoint, err := url.Parse(v.Origin + path)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	response, err := v.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", path, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, into)
}

func shortID(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16] + "…"
}
