package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The proxy runs on a machine nobody vouches for, so what it REFUSES matters
// more than what it serves. Each test below is a way a volunteer gateway could
// turn into something worse than an unreliable one.

func newTestProxy(t *testing.T, origin *httptest.Server) *ContentProxy {
	t.Helper()
	parsed, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse origin: %v", err)
	}
	proxy := NewContentProxy(parsed, parsed.Host, "12D3KooWTest", "")
	return proxy
}

func TestContentProxyServesAndNamesItself(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Syndichan-Signature", "sig")
		w.Header().Set("X-Syndichan-Gateway", "origin")
		_, _ = io.WriteString(w, "<html>thread</html>")
	}))
	defer origin.Close()

	recorder := httptest.NewRecorder()
	newTestProxy(t, origin).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/thread/1", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	// The origin's signature must survive, or the reader has nothing to check.
	if recorder.Header().Get("X-Syndichan-Signature") != "sig" {
		t.Error("origin signature was not preserved")
	}
	// ...and the gateway must replace "origin" with itself, or the observation
	// cannot be attributed to the key that actually served it.
	if got := recorder.Header().Get("X-Syndichan-Gateway"); got != "12D3KooWTest" {
		t.Errorf("gateway header = %q, want the gateway's own id", got)
	}
	if values := recorder.Header().Values("X-Syndichan-Gateway"); len(values) != 1 {
		t.Errorf("gateway header appears %d times; a second value would let it "+
			"claim to be both itself and the origin", len(values))
	}
}

func TestContentProxyRefusesWrites(t *testing.T) {
	reached := false
	origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer origin.Close()
	proxy := newTestProxy(t, origin)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, httptest.NewRequest(method, "/thread/1", strings.NewReader("x")))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, recorder.Code)
		}
	}
	if reached {
		t.Error("a write reached the origin through the gateway; a forged one " +
			"could never be detected after the fact")
	}
}

func TestContentProxyNeverForwardsCookies(t *testing.T) {
	var sawCookie, sawAuth string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCookie = r.Header.Get("Cookie")
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Cookie", "session=secret")
	request.Header.Set("Authorization", "Bearer token")
	newTestProxy(t, origin).ServeHTTP(httptest.NewRecorder(), request)

	if sawCookie != "" {
		t.Errorf("reader's session reached the volunteer: %q", sawCookie)
	}
	if sawAuth != "" {
		t.Errorf("reader's credentials reached the volunteer: %q", sawAuth)
	}
}

func TestContentProxyNeverReturnsSetCookie(t *testing.T) {
	// A gateway that can set a cookie can plant a session of its choosing in a
	// reader's browser, which is a login it controls.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=attacker")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	recorder := httptest.NewRecorder()
	newTestProxy(t, origin).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := recorder.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie survived the gateway: %v", got)
	}
}

func TestContentProxyDeniesPrivilegedPaths(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "SENSITIVE")
	}))
	defer origin.Close()
	proxy := newTestProxy(t, origin)

	for _, path := range []string{"/admin", "/admin/scrapers", "/api/v1/bot/post",
		"/login", "/profile/edit", "/stripe/webhook", "/ADMIN/x"} {
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", path, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "SENSITIVE") {
			t.Errorf("%s: origin body leaked through a denied path", path)
		}
	}
}

func TestContentProxyDoesNotFollowRedirects(t *testing.T) {
	// Following one would let a response choose the gateway's next destination.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "FOLLOWED")
	}))
	defer origin.Close()

	recorder := httptest.NewRecorder()
	newTestProxy(t, origin).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/start", nil))
	if recorder.Code != http.StatusFound {
		t.Errorf("status = %d, want the redirect passed through", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "FOLLOWED") {
		t.Error("the gateway followed a redirect chosen by the response")
	}
}

func TestServiceRoutesControlPlaneBeforeContent(t *testing.T) {
	// A content proxy must never be able to answer /gateway/identity or
	// /readyz: those are how a probe decides this node is who it claims to be.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "IMPOSTOR")
	}))
	defer origin.Close()

	service := NewService(newTestSigner(t), "1.0.0", nil, nil)
	service.SetListenerReady(true)
	service.SetRequireDHTReady(false)
	parsed, _ := url.Parse(origin.URL)
	service.SetContentProxy(NewContentProxy(parsed, parsed.Host, "12D3KooWTest", ""))

	for _, path := range []string{"/healthz", "/readyz", "/gateway/identity"} {
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if strings.Contains(recorder.Body.String(), "IMPOSTOR") {
			t.Errorf("%s was answered by the content proxy", path)
		}
	}

	// And an ordinary path still reaches content.
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/thread/1", nil))
	if !strings.Contains(recorder.Body.String(), "IMPOSTOR") {
		t.Error("content proxy did not serve an ordinary path")
	}
}

func TestContentProxyIsReadableCrossOriginButNeverWithCredentials(t *testing.T) {
	// A reader on syndichan.org must be able to fetch the same object here and
	// compare it. Without CORS the browser hides the response and the only
	// party positioned to audit a gateway cannot.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Syndichan-Hash", "abc")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	recorder := httptest.NewRecorder()
	newTestProxy(t, origin).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
	// With credentials, "*" would expose a logged-in view to any site. The
	// proxy never forwards a cookie, and this is what keeps that guarantee
	// from being quietly undone later.
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got == "true" {
		t.Error("credentials allowed cross-origin: any site could read an authenticated view")
	}
	exposed := recorder.Header().Get("Access-Control-Expose-Headers")
	for _, header := range []string{"X-Syndichan-Hash", "X-Syndichan-Signature", "X-Syndichan-Gateway"} {
		if !strings.Contains(exposed, header) {
			t.Errorf("%s is not exposed; an auditor could not read it", header)
		}
	}
}

func TestControlPlaneIsNotShadowedByAnyMethod(t *testing.T) {
	// A method-qualified route let HEAD /readyz fall through to the content
	// proxy, so the ORIGIN answered the question "is this node ready" -- with a
	// 404, which read to the controller as a broken gateway. Verification then
	// failed and the registration was refused.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "IMPOSTOR")
	}))
	defer origin.Close()

	service := NewService(newTestSigner(t), "1.0.0", nil, nil)
	service.SetListenerReady(true)
	service.SetRequireDHTReady(false)
	parsed, _ := url.Parse(origin.URL)
	service.SetContentProxy(NewContentProxy(parsed, parsed.Host, "12D3KooWTest", ""))

	for _, path := range []string{"/healthz", "/readyz", "/gateway/identity",
		"/gateway/challenge", "/probe/verify"} {
		for _, method := range []string{http.MethodHead, http.MethodPut,
			http.MethodDelete, http.MethodOptions} {
			recorder := httptest.NewRecorder()
			service.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
			if strings.Contains(recorder.Body.String(), "IMPOSTOR") {
				t.Errorf("%s %s was answered by the origin", method, path)
			}
		}
	}
}
