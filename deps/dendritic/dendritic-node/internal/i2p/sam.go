package i2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxSAMLine       = 32 << 10
	commandTimeout   = 75 * time.Second
	defaultSAMMin    = "3.1"
	defaultSAMMax    = "3.3"
	privateKeyMaxLen = 16 << 10
)

// Session is a persistent I2P STREAM session accessed through a local SAM v3
// bridge. The SAM bridge address is deliberately restricted to loopback by the
// configuration layer because SAM is normally unauthenticated and unencrypted.
type Session struct {
	samAddr     string
	id          string
	privateKey  string
	destination string
	base32Host  string
	control     net.Conn

	mu     sync.Mutex
	active map[net.Conn]struct{}
	closed bool
}

// renew re-establishes the SAM session after its control connection has died.
//
// A SAM v3 session lives EXACTLY as long as the TCP control connection that
// issued SESSION CREATE. Routers close idle control sockets, and when that
// happens the router destroys the session -- every later STREAM CONNECT/ACCEPT
// then fails with:
//
//	STREAM STATUS RESULT=INVALID_ID MESSAGE="STREAM SESSION ID ... does not exist"
//
// which is fatal and permanent: the node keeps its listener and its address but
// can neither dial nor be dialled for the rest of the process's life.
//
// The destination private key is persisted, so re-creating the session yields
// the SAME .b32 address. Peers' bootstrap entries and published multiaddrs stay
// valid across a renewal -- that is what makes recovery safe rather than a
// silent identity change.
func (s *Session) renew(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	old := s.control
	s.mu.Unlock()

	// Reuse the EXISTING private key. Calling Open with an empty key path would
	// mint a fresh destination, silently changing this node's address and
	// invalidating every published multiaddr and bootstrap entry pointing at it.
	control, reader, err := connectSAM(ctx, s.samAddr)
	if err != nil {
		return err
	}
	id, err := randomSessionID()
	if err != nil {
		control.Close()
		return err
	}
	command := fmt.Sprintf(
		"SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s "+
			"inbound.length=3 outbound.length=3 inbound.quantity=3 outbound.quantity=3 "+
			"inbound.backupQuantity=1 outbound.backupQuantity=1 i2cp.leaseSetEncType=6,4\n",
		id, s.privateKey,
	)
	if _, err := io.WriteString(control, command); err != nil {
		control.Close()
		return fmt.Errorf("recreate I2P session: %w", err)
	}
	line, err := readSAMLine(reader)
	if err != nil {
		control.Close()
		return fmt.Errorf("read I2P session status: %w", err)
	}
	if resultField(line) != "OK" {
		control.Close()
		return fmt.Errorf("I2P session rejected on renew: %s", safeStatus(line))
	}
	_ = control.SetDeadline(time.Time{})

	s.mu.Lock()
	s.id = id
	s.control = control
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// sessionGone reports whether an error means the router has forgotten our
// session, as opposed to an ordinary per-stream failure.
func sessionGone(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "INVALID_ID") ||
		strings.Contains(text, "does not exist")
}

// Open establishes a persistent STREAM session, generating and persisting an
// Ed25519 I2P destination when this is the first run.
func Open(ctx context.Context, samAddr, keyPath string) (*Session, error) {
	privateKey, err := loadOrCreateDestination(ctx, samAddr, keyPath)
	if err != nil {
		return nil, err
	}
	control, reader, err := connectSAM(ctx, samAddr)
	if err != nil {
		return nil, err
	}
	id, err := randomSessionID()
	if err != nil {
		control.Close()
		return nil, err
	}
	command := fmt.Sprintf(
		"SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s "+
			"inbound.length=3 outbound.length=3 inbound.quantity=3 outbound.quantity=3 "+
			"inbound.backupQuantity=1 outbound.backupQuantity=1 i2cp.leaseSetEncType=6,4\n",
		id, privateKey,
	)
	if _, err := io.WriteString(control, command); err != nil {
		control.Close()
		return nil, fmt.Errorf("create I2P session: %w", err)
	}
	line, err := readSAMLine(reader)
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("read I2P session status: %w", err)
	}
	if resultField(line) != "OK" {
		control.Close()
		return nil, fmt.Errorf("I2P session rejected: %s", safeStatus(line))
	}
	if _, err := io.WriteString(control, "NAMING LOOKUP NAME=ME\n"); err != nil {
		control.Close()
		return nil, fmt.Errorf("query I2P destination: %w", err)
	}
	line, err = readSAMLine(reader)
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("read I2P destination: %w", err)
	}
	destination := field(line, "VALUE")
	if resultField(line) != "OK" || destination == "" {
		control.Close()
		return nil, fmt.Errorf("I2P destination lookup failed: %s", safeStatus(line))
	}
	b32, err := destinationBase32(destination)
	if err != nil {
		control.Close()
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})
	return &Session{
		samAddr: samAddr, id: id, privateKey: privateKey,
		destination: destination, base32Host: b32,
		control: control, active: make(map[net.Conn]struct{}),
	}, nil
}

func loadOrCreateDestination(ctx context.Context, samAddr, keyPath string) (string, error) {
	raw, err := os.ReadFile(keyPath)
	if err == nil {
		if len(raw) > privateKeyMaxLen {
			return "", errors.New("I2P private destination file is too large")
		}
		key := strings.TrimSpace(string(raw))
		if !validDestinationToken(key) {
			return "", errors.New("I2P private destination file is malformed")
		}
		if err := os.Chmod(keyPath, 0600); err != nil {
			return "", fmt.Errorf("secure I2P private destination: %w", err)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	conn, reader, err := connectSAM(ctx, samAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "DEST GENERATE SIGNATURE_TYPE=7\n"); err != nil {
		return "", fmt.Errorf("generate I2P destination: %w", err)
	}
	line, err := readSAMLine(reader)
	if err != nil {
		return "", fmt.Errorf("read generated I2P destination: %w", err)
	}
	privateKey := field(line, "PRIV")
	if !strings.HasPrefix(line, "DEST REPLY") || !validDestinationToken(privateKey) {
		return "", fmt.Errorf("SAM returned an invalid destination: %s", safeStatus(line))
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return "", err
	}
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(file, privateKey+"\n")
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return privateKey, nil
}

func connectSAM(ctx context.Context, samAddr string) (net.Conn, *bufio.Reader, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", samAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to local I2P SAM bridge at %s: %w", samAddr, err)
	}
	if err := setCommandDeadline(conn, ctx); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if _, err := io.WriteString(conn, "HELLO VERSION MIN="+defaultSAMMin+" MAX="+defaultSAMMax+"\n"); err != nil {
		conn.Close()
		return nil, nil, err
	}
	reader := bufio.NewReaderSize(conn, 4096)
	line, err := readSAMLine(reader)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("I2P SAM handshake: %w", err)
	}
	if !strings.HasPrefix(line, "HELLO REPLY") || resultField(line) != "OK" {
		conn.Close()
		return nil, nil, fmt.Errorf("I2P SAM handshake rejected: %s", safeStatus(line))
	}
	return conn, reader, nil
}

// Dial opens a virtual stream to a base32 I2P destination.
func (s *Session) Dial(ctx context.Context, base32Host string) (net.Conn, error) {
	return s.dial(ctx, base32Host, 0)
}

// dial opens a stream, optionally to a specific TO_PORT (0 = unspecified).
func (s *Session) dial(ctx context.Context, base32Host string, toPort int) (net.Conn, error) {
	base32Host = normalizeBase32Host(base32Host)
	if !validBase32Host(base32Host) {
		return nil, errors.New("invalid I2P base32 destination")
	}
	conn, reader, err := connectSAM(ctx, s.samAddr)
	if err != nil {
		return nil, err
	}
	if err := s.track(conn); err != nil {
		conn.Close()
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			s.untrack(conn)
			conn.Close()
		}
	}()
	connect := fmt.Sprintf("STREAM CONNECT ID=%s DESTINATION=%s.b32.i2p SILENT=false", s.id, base32Host)
	if toPort > 0 {
		// TO_PORT reaches a specific port on a single-destination service. The
		// router silently ignores it when it negotiated a pre-3.2 version, so a
		// caller on an old router simply lands on the default port.
		connect += fmt.Sprintf(" TO_PORT=%d", toPort)
	}
	if _, err := io.WriteString(conn, connect+"\n"); err != nil {
		return nil, err
	}
	line, err := readSAMLine(reader)
	if err != nil {
		return nil, fmt.Errorf("I2P stream connect: %w", err)
	}
	if resultField(line) != "OK" {
		// The router has forgotten our session (its control connection died).
		// Renew it -- same destination -- and let the caller retry, rather than
		// failing every dial for the rest of the process's life.
		if status := safeStatus(line); sessionGone(errors.New(status)) {
			if rerr := s.renew(context.Background()); rerr != nil {
				return nil, fmt.Errorf("I2P session lost and renew failed: %v (%s)", rerr, status)
			}
			return nil, fmt.Errorf("I2P session renewed after %s; retry", status)
		}
		return nil, fmt.Errorf("I2P stream connect failed: %s", safeStatus(line))
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return &trackedConn{
		Conn: conn, local: addr(s.base32Host + ".b32.i2p"),
		remote: addr(base32Host + ".b32.i2p"), release: s.untrack,
	}, nil
}

// Accept waits for an inbound virtual stream. The remote I2P destination is
// authenticated by the I2P streaming layer and converted to a base32 address.
func (s *Session) Accept() (net.Conn, error) {
	conn, reader, err := connectSAM(context.Background(), s.samAddr)
	if err != nil {
		return nil, err
	}
	if err := s.track(conn); err != nil {
		conn.Close()
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			s.untrack(conn)
			conn.Close()
		}
	}()
	if _, err := io.WriteString(conn, "STREAM ACCEPT ID="+s.id+" SILENT=false\n"); err != nil {
		return nil, err
	}
	line, err := readSAMLine(reader)
	if err != nil {
		return nil, fmt.Errorf("I2P stream accept: %w", err)
	}
	if resultField(line) != "OK" {
		if status := safeStatus(line); sessionGone(errors.New(status)) {
			if rerr := s.renew(context.Background()); rerr != nil {
				return nil, fmt.Errorf("I2P session lost and renew failed: %v (%s)", rerr, status)
			}
			return nil, fmt.Errorf("I2P session renewed after %s; retry", status)
		}
		return nil, fmt.Errorf("I2P stream accept failed: %s", safeStatus(line))
	}
	// The accept itself may wait indefinitely. Clear the command deadline after
	// SAM confirms the pending accept.
	_ = conn.SetDeadline(time.Time{})
	line, err = readSAMLine(reader)
	if err != nil {
		return nil, fmt.Errorf("I2P inbound destination: %w", err)
	}
	remoteDestination := strings.Fields(line)
	if len(remoteDestination) == 0 || strings.HasPrefix(line, "STREAM STATUS") {
		return nil, errors.New("SAM did not supply an inbound I2P destination")
	}
	remoteB32, err := destinationBase32(remoteDestination[0])
	if err != nil {
		return nil, err
	}
	ok = true
	// SAM v3.2+ appends FROM_PORT/TO_PORT to the accept notification. TO_PORT is
	// the port the remote peer dialed ON US -- which is what lets a SINGLE I2P
	// destination carry up to 65536 distinct ports. We negotiate MAX=3.3, so a
	// modern router supplies it; an older router omits it and toPort stays 0.
	toPort := parsePort(field(line, "TO_PORT"))
	fromPort := parsePort(field(line, "FROM_PORT"))
	return &trackedConn{
		Conn: conn, local: addr(s.base32Host + ".b32.i2p"),
		remote: addr(remoteB32 + ".b32.i2p"), release: s.untrack,
		toPort: toPort, fromPort: fromPort,
	}, nil
}

// AcceptStreamPort is Accept, plus the port the remote peer dialed on this
// destination (SAM v3.2+ TO_PORT). It is how one destination multiplexes many
// ports: a port scan of the destination arrives here as separate accepts, each
// reporting the probed port. Returns 0 when the router does not report a port.
func (s *Session) AcceptStreamPort() (net.Conn, int, error) {
	conn, err := s.Accept()
	if err != nil {
		return nil, 0, err
	}
	if tc, ok := conn.(*trackedConn); ok {
		return conn, tc.toPort, nil
	}
	return conn, 0, nil
}

func parsePort(value string) int {
	if value == "" {
		return 0
	}
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
		if n > 65535 {
			return 0
		}
	}
	return n
}

// DialPort is Dial with an explicit destination port (SAM v3.2+ TO_PORT), so a
// caller can reach a specific port on a single-destination service -- the dial
// side of the multi-port capability. toPort 0 means "unspecified" (port 0).
func (s *Session) DialPort(ctx context.Context, base32Host string, toPort int) (net.Conn, error) {
	if toPort < 0 || toPort > 65535 {
		return nil, errors.New("i2p: TO_PORT out of range")
	}
	return s.dial(ctx, base32Host, toPort)
}

func (s *Session) Base32() string { return s.base32Host }

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	active := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		active = append(active, conn)
	}
	s.active = nil
	control := s.control
	s.mu.Unlock()
	for _, conn := range active {
		_ = conn.Close()
	}
	if control != nil {
		return control.Close()
	}
	return nil
}

func (s *Session) track(conn net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.active[conn] = struct{}{}
	return nil
}

func (s *Session) untrack(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, conn)
}

type trackedConn struct {
	net.Conn
	local, remote    net.Addr
	release          func(net.Conn)
	once             sync.Once
	toPort, fromPort int // SAM v3.2+ per-stream ports; 0 when unreported
}

func (c *trackedConn) LocalAddr() net.Addr  { return c.local }
func (c *trackedConn) RemoteAddr() net.Addr { return c.remote }
func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.release(c.Conn) })
	return err
}

type addr string

func (a addr) Network() string { return "i2p" }
func (a addr) String() string  { return string(a) }

func setCommandDeadline(conn net.Conn, ctx context.Context) error {
	deadline := time.Now().Add(commandTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetDeadline(deadline)
}

func readSAMLine(reader *bufio.Reader) (string, error) {
	var line []byte
	for {
		part, prefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		if len(line)+len(part) > maxSAMLine {
			return "", errors.New("SAM response exceeds maximum line length")
		}
		line = append(line, part...)
		if !prefix {
			return string(line), nil
		}
	}
}

func field(line, name string) string {
	prefix := name + "="
	for _, token := range strings.Fields(line) {
		if strings.HasPrefix(token, prefix) {
			return strings.TrimPrefix(token, prefix)
		}
	}
	return ""
}

func resultField(line string) string { return field(line, "RESULT") }

func safeStatus(line string) string {
	if len(line) > 256 {
		return line[:256] + "..."
	}
	return line
}

func validDestinationToken(value string) bool {
	if len(value) < 884 || len(value) > privateKeyMaxLen {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '~' || char == '=' {
			continue
		}
		return false
	}
	return true
}

func destinationBase32(destination string) (string, error) {
	standard := strings.NewReplacer("-", "+", "~", "/").Replace(destination)
	decoded, err := base64.StdEncoding.DecodeString(standard)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(standard, "="))
	}
	if err != nil || len(decoded) < 387 {
		return "", errors.New("invalid I2P public destination")
	}
	digest := sha256.Sum256(decoded)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])), nil
}

func normalizeBase32Host(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".b32.i2p")
	return value
}

func validBase32Host(value string) bool {
	if len(value) != 52 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			return false
		}
	}
	return true
}

func randomSessionID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "syndichan-" + hex.EncodeToString(value), nil
}
