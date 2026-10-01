package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type registrySigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (s registrySigner) ID() string { return "test-node" }
func (s registrySigner) Sign(value []byte) ([]byte, error) {
	return ed25519.Sign(s.private, value), nil
}
func (s registrySigner) PublicKey() ([]byte, error) { return s.public, nil }
func (s registrySigner) DHTReady() bool             { return true }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestRegistryRequestHasSignatureAndNoReusableSecret(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := registrySigner{public: public, private: private}
	client, err := NewRegistryClient("https://syndichan.org/api/v1/gateways", "gw-001.syndichan.org", signer)
	if err != nil {
		t.Fatal(err)
	}
	client.Now = func() time.Time { return time.Unix(1700000000, 0) }
	client.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		signature, err := base64.RawStdEncoding.DecodeString(request.Header.Get("X-Syndichan-Signature"))
		if err != nil || !ed25519.Verify(public, body, signature) {
			t.Fatal("request signature was invalid")
		}
		if request.Header.Get("Authorization") != "" ||
			strings.Contains(strings.ToLower(string(body)), "token") {
			t.Fatal("request exposed a reusable credential")
		}
		if request.Header.Get("User-Agent") != RegistryUserAgent {
			t.Fatal("unexpected user agent")
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	registration := Registration{NodeID: signer.ID(), HealthState: StateHealthy}
	if err := client.PublishGatewayRegistration(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryEndpointRejectsEmbeddedCredentials(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	_, err := NewRegistryClient(
		"https://user:secret@syndichan.org/api/v1/gateways", "gw-001.syndichan.org",
		registrySigner{private: private},
	)
	if err == nil {
		t.Fatal("credential-bearing endpoint was accepted")
	}
}

func TestReservationPrecedesACMEAndWaitsForMatchingDNS(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := registrySigner{public: public, private: private}
	client, err := NewRegistryClient(
		"https://syndichan.org/api/v1/gateways", "", signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	client.Now = func() time.Time { return time.Unix(1700000000, 0) }
	client.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/api/v1/gateways/reserve" {
			t.Fatalf("unexpected reservation path %s", request.URL.Path)
		}
		body, _ := io.ReadAll(request.Body)
		signature, decodeErr := base64.RawStdEncoding.DecodeString(
			request.Header.Get("X-Syndichan-Signature"),
		)
		if decodeErr != nil || !ed25519.Verify(public, body, signature) {
			t.Fatal("reservation signature was invalid")
		}
		payload, _ := json.Marshal(HostnameReservation{
			Hostname: "gw-derived.syndichan.org",
			IP:       "203.0.113.8", ExpiresAt: 1700000900,
		})
		return &http.Response{
			StatusCode: 201, Body: io.NopCloser(strings.NewReader(string(payload))),
		}, nil
	})
	reservation, err := client.ReserveHostname(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if client.PublicHostname != reservation.Hostname {
		t.Fatal("reserved hostname was not installed on registry client")
	}
	lookups := 0
	client.LookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		if lookups == 1 {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.WaitForReservedDNS(ctx, reservation, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if lookups != 2 {
		t.Fatalf("expected two DNS checks, got %d", lookups)
	}
}

func TestReservationExposesServerRetryAfter(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	client, err := NewRegistryClient(
		"https://syndichan.org/api/v1/gateways", "",
		registrySigner{private: private},
	)
	if err != nil {
		t.Fatal(err)
	}
	client.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     http.Header{"Retry-After": []string{"60"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	_, err = client.ReserveHostname(context.Background())
	var registryError *RegistryHTTPError
	if !errors.As(err, &registryError) {
		t.Fatalf("expected RegistryHTTPError, got %v", err)
	}
	if registryError.StatusCode != http.StatusServiceUnavailable ||
		registryError.RetryAfter != time.Minute {
		t.Fatalf("unexpected registry error: %#v", registryError)
	}
}
