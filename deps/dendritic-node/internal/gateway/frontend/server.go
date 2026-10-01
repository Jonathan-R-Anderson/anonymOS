package frontend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var ErrServerClosed = errors.New("frontend: server closed")

type Config struct {
	OriginAddress string
	LocalAddress  string
	LocalHostname string
	SNIAllowlist  []string
	// SNIRoutes sends specific names somewhere other than the origin, without
	// decrypting them.
	//
	// A volunteer's public 443 is a single socket, but it is not necessarily a
	// single service: a host may already terminate an unrelated name that must
	// keep working after the gateway takes the port. Passing those names through
	// to whatever already served them turns "the gateway displaces that service"
	// into "the gateway carries it", which is the difference between an outage
	// and a port change.
	//
	// Routed names are still passthrough — the gateway never sees their
	// plaintext, and the backend behind them keeps its own certificate.
	SNIRoutes         map[string]string
	MaxConnections    int
	MaxBytesPerSecond int64
	HandshakeTimeout  time.Duration
	DialTimeout       time.Duration
	IdleTimeout       time.Duration
	ProxyProtocol     bool
}

type Server struct {
	config   Config
	allowed  map[string]struct{}
	routes   map[string]string
	logger   interface{ Printf(string, ...any) }
	slots    chan struct{}
	mu       sync.Mutex
	listener net.Listener
	active   map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

func New(config Config, logger interface{ Printf(string, ...any) }) (*Server, error) {
	if config.OriginAddress == "" || config.LocalAddress == "" {
		return nil, errors.New("frontend: origin and local gateway addresses are required")
	}
	localHostname := normalizeHost(config.LocalHostname)
	if localHostname == "" {
		return nil, errors.New("frontend: local gateway hostname is invalid")
	}
	if config.MaxConnections < 1 || config.MaxBytesPerSecond < 1 {
		return nil, errors.New("frontend: connection and bandwidth limits must be positive")
	}
	if config.HandshakeTimeout <= 0 || config.DialTimeout <= 0 || config.IdleTimeout <= 0 {
		return nil, errors.New("frontend: timeouts must be positive")
	}
	allowed := make(map[string]struct{}, len(config.SNIAllowlist))
	for _, hostname := range config.SNIAllowlist {
		normalized := normalizeHost(hostname)
		if normalized == "" || normalized == localHostname {
			return nil, fmt.Errorf("frontend: invalid or duplicate-purpose SNI name %q", hostname)
		}
		allowed[normalized] = struct{}{}
	}
	routes := make(map[string]string, len(config.SNIRoutes))
	for hostname, target := range config.SNIRoutes {
		normalized := normalizeHost(hostname)
		if normalized == "" || normalized == localHostname {
			return nil, fmt.Errorf("frontend: invalid or duplicate-purpose routed SNI name %q", hostname)
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("frontend: route target for %q must be host:port", hostname)
		}
		// A routed name is reachable by definition; requiring it in the
		// allowlist as well would be a second place to forget.
		allowed[normalized] = struct{}{}
		routes[normalized] = target
	}
	if len(allowed) == 0 {
		return nil, errors.New("frontend: origin SNI allowlist is empty")
	}
	config.LocalHostname = localHostname
	return &Server{
		config: config, allowed: allowed, routes: routes, logger: logger,
		slots:  make(chan struct{}, config.MaxConnections),
		active: make(map[net.Conn]struct{}),
	}, nil
}

func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = listener.Close()
		return ErrServerClosed
	}
	if s.listener != nil {
		s.mu.Unlock()
		return errors.New("frontend: Serve called more than once")
	}
	s.listener = listener
	s.mu.Unlock()

	for {
		connection, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return ErrServerClosed
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
			s.track(connection, true)
			s.wg.Add(1)
			go s.handle(connection)
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		for connection := range s.active {
			_ = connection.Close()
		}
		s.mu.Unlock()
		<-done
		return ctx.Err()
	}
}

func (s *Server) handle(client net.Conn) {
	defer func() {
		s.track(client, false)
		_ = client.Close()
		<-s.slots
		s.wg.Done()
	}()
	_ = client.SetReadDeadline(time.Now().Add(s.config.HandshakeTimeout))
	hostname, hello, err := PeekSNI(client)
	if err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	target := s.config.OriginAddress
	sendProxy := s.config.ProxyProtocol
	if hostname == s.config.LocalHostname {
		target = s.config.LocalAddress
		sendProxy = false
	} else if _, allowed := s.allowed[hostname]; !allowed {
		return
	} else if routed, ok := s.routes[hostname]; ok {
		// A co-tenant service on this host. It speaks for itself and holds its
		// own certificate, so the PROXY header the origin expects would be
		// noise at best and a protocol error at worst.
		target = routed
		sendProxy = false
	}
	upstream, err := (&net.Dialer{Timeout: s.config.DialTimeout}).Dial("tcp", target)
	if err != nil {
		return
	}
	s.track(upstream, true)
	defer func() {
		s.track(upstream, false)
		_ = upstream.Close()
	}()

	if sendProxy {
		source, sourceErr := addrPort(client.RemoteAddr())
		destination, destinationErr := addrPort(client.LocalAddr())
		if sourceErr != nil || destinationErr != nil {
			return
		}
		header, headerErr := ProxyHeaderV2(source, destination)
		if headerErr != nil {
			return
		}
		if _, err = upstream.Write(header); err != nil {
			return
		}
	}
	if _, err = upstream.Write(hello); err != nil {
		return
	}

	clientIO := idleConn{Conn: client, timeout: s.config.IdleTimeout}
	upstreamIO := idleConn{Conn: upstream, timeout: s.config.IdleTimeout}
	results := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(&upstreamIO, newPacedReader(&clientIO, s.config.MaxBytesPerSecond))
		closeWrite(upstream)
		results <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(&clientIO, newPacedReader(&upstreamIO, s.config.MaxBytesPerSecond))
		closeWrite(client)
		results <- copyErr
	}()
	<-results
	<-results
}

func (s *Server) track(connection net.Conn, add bool) {
	s.mu.Lock()
	if add {
		s.active[connection] = struct{}{}
	} else {
		delete(s.active, connection)
	}
	s.mu.Unlock()
}

func addrPort(address net.Addr) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	parsedAddress, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.AddrPort{}, err
	}
	parsedPort, err := net.LookupPort("tcp", port)
	if err != nil || parsedPort < 0 || parsedPort > 65535 {
		return netip.AddrPort{}, errors.New("frontend: invalid TCP endpoint")
	}
	return netip.AddrPortFrom(parsedAddress, uint16(parsedPort)), nil
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (connection *idleConn) Read(buffer []byte) (int, error) {
	_ = connection.Conn.SetReadDeadline(time.Now().Add(connection.timeout))
	return connection.Conn.Read(buffer)
}

func (connection *idleConn) Write(buffer []byte) (int, error) {
	_ = connection.Conn.SetWriteDeadline(time.Now().Add(connection.timeout))
	return connection.Conn.Write(buffer)
}

type pacedReader struct {
	reader    io.Reader
	bytes     int64
	started   time.Time
	perSecond int64
}

func newPacedReader(reader io.Reader, perSecond int64) *pacedReader {
	return &pacedReader{reader: reader, started: time.Now(), perSecond: perSecond}
}

func (reader *pacedReader) Read(buffer []byte) (int, error) {
	if int64(len(buffer)) > reader.perSecond {
		buffer = buffer[:reader.perSecond]
	}
	count, err := reader.reader.Read(buffer)
	reader.bytes += int64(count)
	expected := time.Duration(float64(reader.bytes) / float64(reader.perSecond) * float64(time.Second))
	if delay := expected - time.Since(reader.started); delay > 0 {
		time.Sleep(delay)
	}
	return count, err
}

func closeWrite(connection net.Conn) {
	if writer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
	}
}
