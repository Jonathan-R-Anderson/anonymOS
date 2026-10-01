package session

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestHTTPOverASessionSurvivesCarrierDeath: an ordinary net/http server and
// client, the server on a Listener and the client dialling through the
// session, with the carrier killed in the middle of a response body. This is
// the shape the origin server takes over AXON (updates, packages, crash
// reports), so it is tested in that shape.
func TestHTTPOverASessionSurvivesCarrierDeath(t *testing.T) {
	pr := newPair(t, testConfig(), 50*time.Millisecond)
	body := randBytes(t, 3<<20)
	var served atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /release/{name}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		for off := 0; off < len(body); off += 64 << 10 {
			end := off + 64<<10
			if end > len(body) {
				end = len(body)
			}
			w.Write(body[off:end])
			served.Add(int64(end - off))
		}
	})
	mux.HandleFunc("POST /api/v1/crash", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%x", sha256.Sum256(b))
	})
	l := NewListener()
	l.Serve(pr.svc)
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DialContext: pr.cli.DialContext}, Timeout: 30 * time.Second}

	// A POST first, so the connection is in the pool and the GET reuses it.
	report := []byte(`{"report_id":"0123456789abcdef0123456789abcdef"}`)
	resp, err := client.Post("http://origin.axon/api/v1/crash", "application/json", bytes.NewReader(report))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != fmt.Sprintf("%x", sha256.Sum256(report)) {
		t.Fatalf("crash POST answered %q", got)
	}

	killed := make(chan struct{})
	go func() {
		for served.Load() < int64(len(body))/3 {
			time.Sleep(time.Millisecond)
		}
		pr.path().kill(true)
		close(killed)
	}()
	resp, err = client.Get("http://origin.axon/release/os-0.2.1.img")
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading the body across a carrier death: %v", err)
	}
	<-killed
	if !bytes.Equal(got, body) {
		t.Fatalf("release body: %d bytes, want %d, equal=%v", len(got), len(body), bytes.Equal(got, body))
	}
	if pr.cli.Stats().Migrations == 0 {
		t.Fatal("the carrier was killed but nothing migrated")
	}
}
