package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime/runtimetest"
)

// A browser on this machine reaches a hidden service through the proxy, by
// plain HTTP and by CONNECT, and the service sees the port that was asked for.
func TestProxyReachesAxonServices(t *testing.T) {
	seeds := runtimetest.Network(t, 6)
	server := runtimetest.Client(t, seeds)
	var seed [32]byte
	rand.Read(seed[:])
	svc, err := server.Listen(seed)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := svc.Accept()
			if err != nil {
				return
			}
			port := string(conn.(interface{ Meta() []byte }).Meta())
			go http.Serve(&oneConn{conn: conn}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "port %s path %s", port, r.URL.Path)
			}))
		}
	}()

	client := runtimetest.Client(t, seeds)
	proxyServer := httptest.NewServer(New(client.DialContext))
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	httpClient := &http.Client{Timeout: time.Minute, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := httpClient.Get("http://" + svc.Addr() + ":8080/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "port 8080 path /hello" {
		t.Fatalf("plain HTTP through the proxy: %q", body)
	}

	// CONNECT: what HTTPS and raw TCP clients (a port scanner) use.
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:9000 HTTP/1.1\r\nHost: %s:9000\r\n\r\n", svc.Addr(), svc.Addr())
	reader := bufio.NewReader(conn)
	status, _ := reader.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT: %q", status)
	}
	for line, _ := reader.ReadString('\n'); line != "\r\n" && line != ""; line, _ = reader.ReadString('\n') {
	}
	fmt.Fprintf(conn, "GET /tunnel HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	tunnelled, _ := io.ReadAll(reader)
	if !strings.Contains(string(tunnelled), "port 9000 path /tunnel") {
		t.Fatalf("through CONNECT: %q", tunnelled)
	}
}

// Anything that is not an AXON address is refused, never fetched from this
// machine's own address.
func TestProxyRefusesClearnet(t *testing.T) {
	dialed := false
	p := New(func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, fmt.Errorf("should not dial")
	})
	for _, target := range []string{"http://example.com/", "http://127.0.0.1:9090/", "http://abc.b32.i2p/"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", target, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || dialed {
		t.Fatalf("CONNECT to clearnet: status %d, dialed %t", rec.Code, dialed)
	}
}

// oneConn serves exactly one connection as a listener.
type oneConn struct {
	conn net.Conn
	done bool
}

func (o *oneConn) Accept() (net.Conn, error) {
	if o.done {
		select {}
	}
	o.done = true
	return o.conn, nil
}
func (o *oneConn) Close() error   { return nil }
func (o *oneConn) Addr() net.Addr { return o.conn.LocalAddr() }
