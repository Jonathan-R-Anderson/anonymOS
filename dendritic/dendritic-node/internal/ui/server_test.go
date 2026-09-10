package ui

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

type testNode struct{}

func (testNode) ID() string          { return "test-node" }
func (testNode) Addresses() []string { return []string{"/garlic32/test/p2p/12D3Koo"} }
func (testNode) PeerCount() int      { return 3 }

func TestDashboardRejectsDNSRebindingHosts(t *testing.T) {
	for _, allowed := range []string{"localhost:9090", "127.0.0.1:9090", "[::1]:9090"} {
		if !validDashboardHost(allowed) {
			t.Fatalf("local host rejected: %s", allowed)
		}
	}
	for _, denied := range []string{"attacker.example:9090", "0.0.0.0:9090", "192.168.1.4:9090"} {
		if validDashboardHost(denied) {
			t.Fatalf("non-local host accepted: %s", denied)
		}
	}
}

// The dashboard on a LAN address is an admin panel on someone's network: it
// must answer nothing at all until the caller proves it is the operator.
func TestLANDashboardDemandsThePassword(t *testing.T) {
	const (
		listen   = "192.168.1.50:9090"
		password = "correct-horse-battery-staple"
	)
	server := New(nil, testNode{}, log.New(io.Discard, "", 0))
	server.SetAccessControl(listen, "admin", password)

	get := func(user, pass string, withAuth bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "http://"+listen+"/", nil)
		request.Host = listen
		if withAuth {
			request.SetBasicAuth(user, pass)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}

	anonymous := get("", "", false)
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated LAN request returned %d, not 401", anonymous.Code)
	}
	if !strings.HasPrefix(anonymous.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatal("no Basic challenge, so a browser has no way to ask for the password")
	}
	// The page must not leak through the challenge.
	if strings.Contains(anonymous.Body.String(), "csrf") {
		t.Fatal("the dashboard body was served to an unauthenticated caller")
	}
	for _, wrong := range [][2]string{
		{"admin", "wrong"}, {"admin", ""}, {"root", password}, {"", password},
		{"admin", password + "x"},
	} {
		if code := get(wrong[0], wrong[1], true).Code; code != http.StatusUnauthorized {
			t.Fatalf("credential %q/%q returned %d, not 401", wrong[0], wrong[1], code)
		}
	}
	correct := get("admin", password, true)
	if correct.Code != http.StatusOK {
		t.Fatalf("the correct credential returned %d: %s", correct.Code, correct.Body.String())
	}
	// Mutating routes are behind the same gate, not only the read-only page.
	post := httptest.NewRequest(http.MethodPost, "http://"+listen+"/capacity",
		strings.NewReader("capacity_gib=1"))
	post.Host = listen
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, post)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated POST returned %d, not 401", response.Code)
	}
}

// If validation is ever bypassed -- an older config file, a future caller that
// forgets -- the page must go dark rather than open. No password on a network
// address is worse than no dashboard.
func TestLANDashboardWithoutAPasswordServesNothing(t *testing.T) {
	server := New(nil, testNode{}, log.New(io.Discard, "", 0))
	server.SetAccessControl("192.168.1.50:9090", "admin", "")
	request := httptest.NewRequest(http.MethodGet, "http://192.168.1.50:9090/", nil)
	request.Host = "192.168.1.50:9090"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("a passwordless LAN dashboard returned %d, not 503", response.Code)
	}
	if strings.Contains(response.Body.String(), "csrf") {
		t.Fatal("the dashboard body was served with no password configured")
	}
}

// Loopback is unchanged: no credential is configured, none is demanded, and
// every existing install keeps working exactly as it did.
func TestLoopbackDashboardAsksForNothing(t *testing.T) {
	server := New(nil, testNode{}, log.New(io.Discard, "", 0))
	server.SetAccessControl("127.0.0.1:9090", "admin", "")
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("loopback dashboard returned %d: %s", response.Code, response.Body.String())
	}
}

// Authenticating does not switch the rebinding defence off. A hostile page that
// points its own domain at the node's LAN address still gets nowhere, and the
// browser would not hand it the saved credential for that origin either.
func TestLANDashboardStillRefusesForeignHosts(t *testing.T) {
	const password = "correct-horse-battery-staple"
	server := New(nil, testNode{}, log.New(io.Discard, "", 0))
	server.SetAccessControl("192.168.1.50:9090", "admin", password)
	request := httptest.NewRequest(http.MethodGet, "http://192.168.1.50:9090/", nil)
	request.Host = "attacker.example:9090"
	request.SetBasicAuth("admin", password)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("a rebound host returned %d, not 421", response.Code)
	}
	// The address it was actually bound to is what it answers to.
	for _, host := range []string{"192.168.1.50:9090", "127.0.0.1:9090", "localhost:9090"} {
		if !server.validRequestHost(host) {
			t.Fatalf("the dashboard refuses its own address %s", host)
		}
	}
	if server.validRequestHost("192.168.1.51:9090") {
		t.Fatal("an address this page was never bound to was accepted")
	}
}

func TestUserCanPersistStorageAllocation(t *testing.T) {
	storage, err := store.Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	server := New(storage, testNode{}, log.New(io.Discard, "", 0))
	form := url.Values{
		"csrf":         {server.csrf},
		"capacity_gib": {"1.5"},
	}
	request := httptest.NewRequest(
		http.MethodPost, "http://127.0.0.1:9090/capacity",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("capacity update returned %d: %s", response.Code, response.Body.String())
	}
	if storage.Capacity() != int64(1.5*(1<<30)) {
		t.Fatalf("capacity was not updated: %d", storage.Capacity())
	}
}

func TestCapacityUpdateRequiresCSRF(t *testing.T) {
	storage, err := store.Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	server := New(storage, testNode{}, log.New(io.Discard, "", 0))
	request := httptest.NewRequest(
		http.MethodPost, "http://127.0.0.1:9090/capacity",
		strings.NewReader("capacity_gib=1"),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF returned %d", response.Code)
	}
}
