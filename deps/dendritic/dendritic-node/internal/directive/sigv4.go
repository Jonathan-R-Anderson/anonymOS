package directive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Signing a request to this node's OWN object store.
//
// The directive is published to the object store under a fixed key because that
// is the one place a node can read it without the origin being up, its domain
// resolving, or its certificate being valid. The endpoint is the node's own S3
// gateway, which requires SigV4 — so an unsigned GET returns 403 and the
// domain-independent path silently does not exist.
//
// The credentials are the node's own, from its own config file, for a service
// listening on its own loopback interface. Nothing is being granted to anybody:
// this is the node proving to itself that it is itself.
//
// EMPTY-PAYLOAD GET ONLY
// That is all this needs to do, and a general signer would be considerably more
// code with more ways to be subtly wrong. Anything else should use a real SDK.

const (
	sigv4Algorithm = "AWS4-HMAC-SHA256"
	// The hash of an empty body, which every GET here has. Precomputed because
	// it is a constant of the specification.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Credentials for the node's own S3 endpoint.
type Credentials struct {
	AccessKey string
	SecretKey string
	Region    string
}

func (c Credentials) region() string {
	if c.Region == "" {
		return "us-east-1"
	}
	return c.Region
}

// SignGet adds SigV4 authentication headers to an empty-payload GET.
//
// `now` is a parameter rather than read from the clock so the signature is
// reproducible in a test — a signer verified only against itself is a signer
// verified against nothing.
func SignGet(request *http.Request, creds Credentials, now time.Time) {
	if creds.AccessKey == "" || creds.SecretKey == "" {
		return
	}
	now = now.UTC()
	stamp := now.Format("20060102T150405Z")
	day := now.Format("20060102")

	request.Header.Set("X-Amz-Date", stamp)
	request.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	if request.Host != "" {
		request.Header.Set("Host", request.Host)
	} else {
		request.Header.Set("Host", request.URL.Host)
	}

	signedHeaders, canonicalHeaders := canonicalHeaders(request)
	canonicalRequest := strings.Join([]string{
		request.Method,
		canonicalPath(request.URL.EscapedPath()),
		request.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		emptyPayloadHash,
	}, "\n")

	scope := strings.Join([]string{day, creds.region(), "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		sigv4Algorithm,
		stamp,
		scope,
		hex.EncodeToString(sha256sum([]byte(canonicalRequest))),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+creds.SecretKey), day)
	key = hmacSHA256(key, creds.region())
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	request.Header.Set("Authorization", strings.Join([]string{
		sigv4Algorithm + " Credential=" + creds.AccessKey + "/" + scope,
		"SignedHeaders=" + signedHeaders,
		"Signature=" + signature,
	}, ", "))
}

func canonicalPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func canonicalHeaders(request *http.Request) (string, string) {
	// host, x-amz-content-sha256 and x-amz-date are the three that matter for
	// an empty GET. Signing every header would break the moment a proxy or the
	// Go runtime adds one the server did not see.
	wanted := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(wanted)

	var names []string
	var lines strings.Builder
	for _, name := range wanted {
		value := request.Header.Get(name)
		if name == "host" && value == "" {
			value = request.URL.Host
		}
		if value == "" {
			continue
		}
		names = append(names, name)
		lines.WriteString(name)
		lines.WriteString(":")
		lines.WriteString(strings.TrimSpace(value))
		lines.WriteString("\n")
	}
	return strings.Join(names, ";"), lines.String()
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
