package ethproof

import "testing"

// The bug the first live run found: a successful batch of sixty headers was
// classified as a rate limit because ordinary block hashes contain "429".
//
// Fail-closed made it safe and made it look like a permanent provider outage,
// which is the expensive kind of safe.
func TestRateLimitDetectorIgnoresResponseBodies(t *testing.T) {
	realish := `[{"id":0,"result":{"hash":"0x429ab7c1e4295f...","number":"0x1"}}]`
	if isRateLimit(200, realish) {
		t.Fatal("a successful batch body was read as a rate limit; the detector " +
			"must only ever see a decoded error message")
	}
	for _, msg := range []string{
		"Your app has exceeded its compute units per second capacity.",
		"rate limit exceeded",
		"Too Many Requests",
	} {
		if !isRateLimit(200, msg) {
			t.Errorf("a real refusal was missed: %q", msg)
		}
	}
	if !isRateLimit(429, "") {
		t.Error("HTTP 429 with no body must count")
	}
	if isRateLimit(200, "") {
		t.Error("an empty message on a 200 must not count")
	}
	// "exceeded" alone is too loose to be a marker, but must still be caught in
	// the phrases that really occur.
	if isRateLimit(200, "block number exceeded the chain head") {
		t.Error("a non-capacity error containing 'exceeded' was misread")
	}
}
