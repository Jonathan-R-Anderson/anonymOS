package s3api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Authenticator struct {
	AccessKey string
	SecretKey string
	Now       func() time.Time
}

type AuthResult struct {
	PayloadHash string
}

func (a Authenticator) Verify(r *http.Request) (AuthResult, error) {
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") {
		return AuthResult{}, errors.New("AWS Signature Version 4 is required")
	}
	values := parseAuthorization(strings.TrimPrefix(authorization, "AWS4-HMAC-SHA256 "))
	credential := strings.Split(values["Credential"], "/")
	if len(credential) != 5 || credential[0] != a.AccessKey ||
		credential[4] != "aws4_request" || credential[3] != "s3" {
		return AuthResult{}, errors.New("invalid credential scope")
	}
	dateValue := r.Header.Get("X-Amz-Date")
	requestTime, err := time.Parse("20060102T150405Z", dateValue)
	if err != nil || credential[1] != requestTime.UTC().Format("20060102") {
		return AuthResult{}, errors.New("invalid request date")
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	if delta := now.Sub(requestTime); delta > 15*time.Minute || delta < -15*time.Minute {
		return AuthResult{}, errors.New("request time is outside the allowed clock skew")
	}
	signedHeaders := strings.Split(values["SignedHeaders"], ";")
	if len(signedHeaders) == 0 || !contains(signedHeaders, "host") ||
		!contains(signedHeaders, "x-amz-content-sha256") || !contains(signedHeaders, "x-amz-date") {
		return AuthResult{}, errors.New("required signed headers are missing")
	}
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		return AuthResult{}, errors.New("payload hash is required")
	}
	if payloadHash == "UNSIGNED-PAYLOAD" && !requestIsLoopback(r) && r.TLS == nil {
		return AuthResult{}, errors.New("unsigned payload requires TLS or loopback transport")
	}
	canonicalHeaders, err := canonicalHeaders(r, signedHeaders)
	if err != nil {
		return AuthResult{}, err
	}
	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI(r.URL),
		canonicalQuery(r.URL.Query()),
		canonicalHeaders,
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	scope := strings.Join(credential[1:], "/")
	requestDigest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", dateValue, scope, hex.EncodeToString(requestDigest[:]),
	}, "\n")
	signingKey := hmacSHA256([]byte("AWS4"+a.SecretKey), credential[1])
	signingKey = hmacSHA256(signingKey, credential[2])
	signingKey = hmacSHA256(signingKey, credential[3])
	signingKey = hmacSHA256(signingKey, credential[4])
	expected := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	actual := strings.ToLower(values["Signature"])
	if len(actual) != len(expected) || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return AuthResult{}, errors.New("signature mismatch")
	}
	return AuthResult{PayloadHash: payloadHash}, nil
}

func parseAuthorization(value string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(value, ",") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) == 2 {
			result[pair[0]] = pair[1]
		}
	}
	return result
}

func canonicalHeaders(r *http.Request, names []string) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	if strings.Join(sorted, ";") != strings.Join(names, ";") {
		return "", errors.New("signed headers must be sorted")
	}
	var builder strings.Builder
	for _, name := range names {
		if name != strings.ToLower(name) {
			return "", errors.New("signed header names must be lowercase")
		}
		var value string
		if name == "host" {
			value = r.Host
		} else {
			values, ok := r.Header[http.CanonicalHeaderKey(name)]
			if !ok {
				return "", fmt.Errorf("signed header %s is absent", name)
			}
			value = strings.Join(values, ",")
		}
		builder.WriteString(name)
		builder.WriteByte(':')
		builder.WriteString(strings.Join(strings.Fields(value), " "))
		builder.WriteByte('\n')
	}
	return builder.String(), nil
}

func canonicalURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func canonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var pairs []string
	for _, key := range keys {
		items := append([]string(nil), values[key]...)
		sort.Strings(items)
		for _, value := range items {
			pairs = append(pairs, awsEncode(key)+"="+awsEncode(value))
		}
	}
	return strings.Join(pairs, "&")
}

func awsEncode(value string) string {
	const hexChars = "0123456789ABCDEF"
	var builder strings.Builder
	for _, b := range []byte(value) {
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' ||
			b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == '~' {
			builder.WriteByte(b)
		} else {
			builder.WriteByte('%')
			builder.WriteByte(hexChars[b>>4])
			builder.WriteByte(hexChars[b&15])
		}
	}
	return builder.String()
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func requestIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
