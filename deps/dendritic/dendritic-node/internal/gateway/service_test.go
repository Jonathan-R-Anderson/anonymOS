package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChallengeIsAuthenticatedAndOneUse(t *testing.T) {
	candidate := newTestSigner(t)
	probe := newTestSigner(t)
	service := NewService(candidate, "test", map[string]string{
		probe.ID(): publicKeyString(t, probe),
	}, nil)
	fixed := time.Unix(1_800_000_000, 0)
	service.now = func() time.Time { return fixed }
	challenge := ChallengeRequest{
		ChallengeID: "unique", Nonce: "sufficiently-random-nonce",
		IssuedAt: fixed.Unix(), ExpiresAt: fixed.Add(30 * time.Second).Unix(),
		ProbeID: probe.ID(),
	}
	if err := SignChallenge(probe, &challenge); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(challenge)
	send := func(remote string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/gateway/challenge", bytes.NewReader(raw))
		request.RemoteAddr = remote
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		return response
	}
	first := send("8.8.8.8:1234")
	if first.Code != http.StatusOK {
		t.Fatalf("first challenge returned %d: %s", first.Code, first.Body.String())
	}
	// A different source bypasses only the per-IP cadence, not replay defense.
	second := send("1.1.1.1:1234")
	if second.Code != http.StatusConflict {
		t.Fatalf("replay returned %d: %s", second.Code, second.Body.String())
	}
}

func TestUnadmittedProbeIsRejected(t *testing.T) {
	candidate := newTestSigner(t)
	probe := newTestSigner(t)
	service := NewService(candidate, "test", nil, nil)
	now := time.Now()
	challenge := ChallengeRequest{
		ChallengeID: "unique", Nonce: "nonce", IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30 * time.Second).Unix(), ProbeID: probe.ID(),
	}
	_ = SignChallenge(probe, &challenge)
	raw, _ := json.Marshal(challenge)
	request := httptest.NewRequest(http.MethodPost, "/gateway/challenge", bytes.NewReader(raw))
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unadmitted probe returned %d", response.Code)
	}
}
