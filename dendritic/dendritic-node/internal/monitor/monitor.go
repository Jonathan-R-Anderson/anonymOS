// Package monitor checks that Syndichan answers, from wherever this node is,
// and publishes the result to the public status page at /status.
//
// # WHY THE NODE DOES THIS AND NOT THE SERVER
//
// A status page served by the thing it monitors reports "all systems
// operational" right up until it stops answering, and then reports nothing. The
// outage and the page's ability to describe the outage fail together, at the
// one moment the page exists for.
//
// So the checks happen out here. Each monitor sees a different path through the
// internet, which is also the only way to tell "the site is down" apart from
// "the site is unreachable from one network" — a distinction a single vantage
// point cannot make, however well instrumented it is.
//
// # WHY THE CHECK LIST IS FETCHED RATHER THAN COMPILED IN
//
// A monitoring fleet whose checks live in the binary can only ever be as
// current as its slowest operator. The list comes from the coordinator so it
// can change without every volunteer updating anything.
//
// NOTHING HERE MAY TAKE DOWN THE NODE. Every failure is logged and swallowed.
// Monitoring is a courtesy this node performs for other people; it is never
// worth interrupting the storage or gateway work it was actually run for.
package monitor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	// UserAgent matches the storage client's, which the coordinator requires.
	UserAgent = "Syndichan-Storage-Client/1.0"

	// DefaultInterval is used only until the coordinator states its own. It is
	// a floor rather than a schedule -- see jitter below.
	DefaultInterval = 60 * time.Second

	// A probe is a check, not a download. Anything past this is a failure
	// however much of a body is still arriving, so the reader is bounded to
	// keep a hostile or broken target from holding memory.
	maxProbeBytes = 64 << 10

	maxResponseBytes = 64 << 10

	// Ceiling on how long one full round may take, so a pathological target
	// list cannot stall the loop past its own interval.
	roundTimeout = 5 * time.Minute
)

// Signer is the persistent node identity, satisfied by the same types the
// heartbeat uses. Reports are signed with it so the public page cannot be
// written by anybody who can reach the endpoint.
type Signer interface {
	ID() string
	Sign([]byte) ([]byte, error)
}

type logf interface{ Printf(string, ...any) }

// Target is one thing to check, as the coordinator describes it.
type Target struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeout_ms"`
}

type targetsResponse struct {
	Version         int      `json:"version"`
	Targets         []Target `json:"targets"`
	IntervalSeconds int      `json:"interval_seconds"`
	ReportURL       string   `json:"report_url"`
}

// Result is one check's outcome.
type Result struct {
	Key       string `json:"key"`
	OK        bool   `json:"ok"`
	LatencyMS *int   `json:"latency_ms"`
	Detail    string `json:"detail,omitempty"`
}

type report struct {
	Version   int      `json:"version"`
	NodeID    string   `json:"node_id"`
	Timestamp int64    `json:"timestamp"`
	Results   []Result `json:"results"`
}

// Client runs the probe loop.
type Client struct {
	Signer Signer
	// TargetsURL is asked what to check and where to send the answer.
	TargetsURL string
	// ReportURL overrides what the coordinator returns. Normally empty: taking
	// it from the same response as the targets keeps one source of truth.
	ReportURL string
	HTTP      *http.Client
	Logger    logf
}

// DirectHTTPClient is the transport probes must use: no proxy.
//
// Probing through I2P would measure I2P. The question this answers is whether
// an ordinary reader on the ordinary internet can reach the site, so the
// request has to leave the way an ordinary reader's would.
func DirectHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

func (c *Client) logger() logf {
	if c.Logger == nil {
		return discard{}
	}
	return c.Logger
}

type discard struct{}

func (discard) Printf(string, ...any) {}

// Run probes forever, on the interval the coordinator asks for, until ctx ends.
//
// The first round is deliberately delayed by a jittered fraction of the
// interval rather than run immediately: a fleet that all start after the same
// deploy would otherwise arrive together forever, turning monitoring into a
// synchronized load test against the thing it is supposed to be measuring.
func (c *Client) Run(ctx context.Context) {
	interval := DefaultInterval
	timer := time.NewTimer(jitter(interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if next := c.Once(ctx); next > 0 {
				interval = next
			}
			timer.Reset(jitter(interval))
		}
	}
}

// Once fetches the target list, probes everything on it, and posts the report.
// Returns the interval the coordinator asked for, or 0 if it did not say.
func (c *Client) Once(ctx context.Context) time.Duration {
	ctx, cancel := context.WithTimeout(ctx, roundTimeout)
	defer cancel()

	targets, err := c.fetchTargets(ctx)
	if err != nil {
		c.logger().Printf("monitor: could not read the target list: %v", err)
		return 0
	}
	if len(targets.Targets) == 0 {
		return time.Duration(targets.IntervalSeconds) * time.Second
	}

	results := make([]Result, 0, len(targets.Targets))
	for _, target := range targets.Targets {
		results = append(results, c.probe(ctx, target))
	}

	reportURL := c.ReportURL
	if reportURL == "" {
		reportURL = targets.ReportURL
	}
	if reportURL == "" {
		c.logger().Printf("monitor: no report URL; %d results discarded", len(results))
		return time.Duration(targets.IntervalSeconds) * time.Second
	}
	if err := c.send(ctx, reportURL, results); err != nil {
		c.logger().Printf("monitor: could not send the report: %v", err)
	}
	return time.Duration(targets.IntervalSeconds) * time.Second
}

func (c *Client) fetchTargets(ctx context.Context) (targetsResponse, error) {
	var out targetsResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.TargetsURL, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.client().Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	return out, nil
}

// probe checks one target and reports what happened, including when what
// happened was a failure. A monitor that quietly drops failures is worse than
// no monitor: the page would show fewer checks rather than a worse result, so
// an outage would read as a slow day.
func (c *Client) probe(ctx context.Context, target Target) Result {
	timeout := time.Duration(target.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	result := Result{Key: target.Key}

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target.URL, nil)
	if err != nil {
		result.Detail = sanitiseDetail("bad target url: " + err.Error())
		return result
	}
	req.Header.Set("User-Agent", UserAgent)
	// Never reuse a cached answer: the question is whether the origin is
	// answering right now, and a 304 from somewhere in between answers a
	// different question entirely.
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.client().Do(req)
	if err != nil {
		result.Detail = sanitiseDetail(err.Error())
		return result
	}
	defer resp.Body.Close()
	// Drained so the connection can be reused, and bounded so a target that
	// streams forever cannot exhaust this node's memory.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBytes))

	elapsed := int(time.Since(started) / time.Millisecond)
	// 2xx and 3xx both mean the service answered. Following redirects is the
	// http client's business; a redirect that arrives is still a live server.
	result.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
	if !result.OK {
		result.Detail = sanitiseDetail(resp.Status)
	}
	// Latency is attached only to successes. A timeout produces a duration
	// equal to the timeout, and reporting it as latency would make an outage
	// look like a slowdown on the page.
	if result.OK {
		result.LatencyMS = &elapsed
	}
	return result
}

func (c *Client) send(ctx context.Context, url string, results []Result) error {
	body, err := json.Marshal(report{
		Version:   1,
		NodeID:    c.Signer.ID(),
		Timestamp: time.Now().UTC().Unix(),
		Results:   results,
	})
	if err != nil {
		return err
	}
	// The signature covers the exact bytes that will be sent, not a digest this
	// node computed: signing a digest would let the sender choose what the
	// signature attests to.
	signature, err := c.Signer.Sign(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("X-Syndichan-Node", c.Signer.ID())
	req.Header.Set("X-Syndichan-Signature", base64.RawURLEncoding.EncodeToString(signature))

	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode >= 400 {
		return &httpError{Status: resp.Status}
	}
	return nil
}

type httpError struct{ Status string }

func (e *httpError) Error() string { return "report refused: " + e.Status }

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return DirectHTTPClient()
}

// jitter spreads a fleet across the interval instead of letting it converge.
//
// Between 75% and 125% of the requested interval. Without this, every monitor
// started by the same rollout stays in lockstep indefinitely, and the checks
// arrive as one burst per minute -- which measures how the site handles a
// thundering herd rather than how it serves anybody.
//
// crypto/rand rather than math/rand so a node does not need a seeded PRNG for
// this alone; if it fails, the un-jittered interval is a correct fallback.
func jitter(interval time.Duration) time.Duration {
	if interval <= 0 {
		interval = DefaultInterval
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return interval
	}
	span := int64(interval / 2)
	if span <= 0 {
		return interval
	}
	offset := int64(binary.BigEndian.Uint64(buf[:])%uint64(span)) - span/2
	return interval + time.Duration(offset)
}

// maxDetail bounds the free-text field a schema audit cannot see into (T16.3).
//
// T16.3 forbids a per-circuit, per-name or per-peer identifier in telemetry, and
// it is enforced by a SCHEMA audit -- which checks field NAMES. `Detail` passes
// that check by name and can carry whatever a caller puts in it, so it is the
// one field where the rule has to be about contents instead.
const maxDetail = 200

// ipInError matches a bare IPv4 address or a bracketed IPv6 one.
var ipInError = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b|\[[0-9a-fA-F:]+\]`)

// sanitiseDetail bounds and redacts a probe's error text before it is reported.
//
// Go's HTTP errors are the specific problem. A failed request produces something
// like
//
//	Get "https://example/x": dial tcp 203.0.113.9:443: connect: connection refused
//
// which carries the RESOLVED ADDRESS of the target. The targets are supplied by
// the site rather than chosen by a user, so this is not somebody's browsing
// history -- but it is still an address this node observed being sent to a
// server, and "the useful field and the dangerous field are the same field" is
// exactly what §23's P16 card warns about. The status code and the failure kind
// are what make a probe useful; the IP adds nothing an operator needs.
func sanitiseDetail(detail string) string {
	detail = ipInError.ReplaceAllString(detail, "[redacted]")
	if len(detail) > maxDetail {
		// Truncated rather than dropped: "connection refused" is the whole value
		// of the field, and it is at the end of a long Go error.
		detail = detail[:maxDetail] + "..."
	}
	return detail
}
