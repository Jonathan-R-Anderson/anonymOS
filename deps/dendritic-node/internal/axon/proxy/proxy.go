// Package proxy is a loopback HTTP proxy onto the AXON overlay: how a person
// on this machine reaches a <56 base32>.key.axon address with an ordinary
// browser, curl or port scanner -- the job the I2P router's HTTP proxy did for
// .i2p addresses.
//
// It reaches AXON addresses and nothing else. There is no exit to clearnet,
// so a request for any other host is refused rather than quietly sent from
// this machine's own address: a proxy that sometimes anonymises is one nobody
// can rely on.
package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

// Dialer opens a stream to "<addr>.key.axon:port". *runtime.Runtime's
// DialContext satisfies it.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Handler serves both proxy forms: CONNECT host:port (HTTPS, and any TCP
// protocol a client tunnels) and absolute-form plain HTTP requests.
type Handler struct {
	Dial Dialer
	// DialTimeout bounds reaching a service. Zero means two minutes, which
	// covers a cold rendezvous.
	DialTimeout time.Duration

	transport *http.Transport
}

// New returns a proxy over dial.
func New(dial Dialer) *Handler {
	h := &Handler{Dial: dial}
	h.transport = &http.Transport{
		DialContext:         func(ctx context.Context, network, addr string) (net.Conn, error) { return h.dial(ctx, addr) },
		Proxy:               nil,
		MaxIdleConnsPerHost: 4,
	}
	return h
}

// ErrNotAxon is the refusal for any host that is not an AXON address.
var ErrNotAxon = errors.New("only <56 base32>.key.axon addresses are reachable through this proxy")

func (h *Handler) dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "80"
	}
	if _, err := identity.ParseAddress(host); err != nil || !strings.HasSuffix(strings.ToLower(host), ".key.axon") {
		return nil, ErrNotAxon
	}
	timeout := h.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return h.Dial(ctx, "tcp", net.JoinHostPort(strings.ToLower(host), port))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.connect(w, r)
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		http.Error(w, "this is a proxy: send absolute-form http:// requests, or CONNECT", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopByHop(out.Header)
	resp, err := h.transport.RoundTrip(out)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrNotAxon) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer resp.Body.Close()
	removeHopByHop(resp.Header)
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	upstream, err := h.dial(r.Context(), r.Host)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrNotAxon) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "CONNECT is not supported on this connection", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() {
		if buffered.Reader.Buffered() > 0 {
			io.CopyN(upstream, buffered, int64(buffered.Reader.Buffered()))
		}
		io.Copy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
	client.Close()
	upstream.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func removeHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}
