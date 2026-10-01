package directive

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEmptyPayloadHashIsRight(t *testing.T) {
	// Hardcoded from the specification, so it is checked against the actual
	// function rather than against my memory of the constant. A wrong value
	// here produces a signature the server rejects with no clue why.
	sum := sha256.Sum256(nil)
	if got := hex.EncodeToString(sum[:]); got != emptyPayloadHash {
		t.Fatalf("constant is wrong\n got %s\nwant %s", emptyPayloadHash, got)
	}
	if len(emptyPayloadHash) != 64 {
		t.Fatalf("hash is %d chars, want 64", len(emptyPayloadHash))
	}
}

func signed(t *testing.T, url string, creds Credentials) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	SignGet(request, creds, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	return request
}

func TestSignatureShape(t *testing.T) {
	request := signed(t, "http://127.0.0.1:9000/directives/current",
		Credentials{AccessKey: "AKIAEXAMPLE", SecretKey: "s3cr3t"})

	auth := request.Header.Get("Authorization")
	for _, want := range []string{
		"AWS4-HMAC-SHA256",
		"Credential=AKIAEXAMPLE/20260801/us-east-1/s3/aws4_request",
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date",
		"Signature=",
	} {
		if !strings.Contains(auth, want) {
			t.Fatalf("missing %q in %q", want, auth)
		}
	}
	if request.Header.Get("X-Amz-Date") != "20260801T120000Z" {
		t.Fatalf("date header: %q", request.Header.Get("X-Amz-Date"))
	}
}

func TestSignatureIsDeterministic(t *testing.T) {
	// Same request, same moment, same credentials -> same signature. If this
	// varies, the signer is reading something it was not given and the failure
	// only appears against a real server.
	creds := Credentials{AccessKey: "AKIAEXAMPLE", SecretKey: "s3cr3t"}
	first := signed(t, "http://127.0.0.1:9000/directives/current", creds)
	second := signed(t, "http://127.0.0.1:9000/directives/current", creds)
	if first.Header.Get("Authorization") != second.Header.Get("Authorization") {
		t.Fatal("the same request signed twice produced different signatures")
	}
}

func TestEverythingSignedActuallyChangesTheSignature(t *testing.T) {
	// Each of these is covered by the canonical request. If changing one does
	// not change the signature, it is not really being signed and a server
	// that checks it will reject us for reasons nothing here would explain.
	creds := Credentials{AccessKey: "AKIAEXAMPLE", SecretKey: "s3cr3t"}
	base := signed(t, "http://127.0.0.1:9000/directives/current", creds).
		Header.Get("Authorization")

	cases := map[string]*http.Request{
		"different path": signed(t, "http://127.0.0.1:9000/directives/other", creds),
		"different host": signed(t, "http://127.0.0.1:9001/directives/current", creds),
		"different query": signed(t,
			"http://127.0.0.1:9000/directives/current?x=1", creds),
		"different secret": signed(t, "http://127.0.0.1:9000/directives/current",
			Credentials{AccessKey: "AKIAEXAMPLE", SecretKey: "other"}),
		"different key": signed(t, "http://127.0.0.1:9000/directives/current",
			Credentials{AccessKey: "OTHER", SecretKey: "s3cr3t"}),
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			if request.Header.Get("Authorization") == base {
				t.Fatal("the signature did not change")
			}
		})
	}
}

func TestTimeChangesTheSignature(t *testing.T) {
	creds := Credentials{AccessKey: "AKIAEXAMPLE", SecretKey: "s3cr3t"}
	request, _ := http.NewRequest(http.MethodGet,
		"http://127.0.0.1:9000/directives/current", nil)
	SignGet(request, creds, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	first := request.Header.Get("Authorization")

	other, _ := http.NewRequest(http.MethodGet,
		"http://127.0.0.1:9000/directives/current", nil)
	SignGet(other, creds, time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC))
	if other.Header.Get("Authorization") == first {
		t.Fatal("a different day produced the same signature")
	}
}

func TestNoCredentialsSignsNothing(t *testing.T) {
	// A node with no S3 credentials must not send a half-built Authorization
	// header: a malformed one is refused with a different error than an absent
	// one, and the absent case is the honest description.
	request := signed(t, "http://127.0.0.1:9000/directives/current", Credentials{})
	if request.Header.Get("Authorization") != "" {
		t.Fatalf("signed without credentials: %q", request.Header.Get("Authorization"))
	}
}
