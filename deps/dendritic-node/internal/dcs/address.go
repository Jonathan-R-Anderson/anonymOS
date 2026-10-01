package dcs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// SessionOpener creates an I2P session from a key file, returning something
// that knows its own base32 address. internal/i2p.Session satisfies this; the
// interface exists so the allocator is testable without a SAM bridge.
type SessionOpener interface {
	Open(ctx context.Context, keyPath string) (Session, error)
}

type Session interface {
	Base32() string
	// AcceptStreamPort accepts an inbound stream on this destination and reports
	// the port the caller dialed. It is here so ONE session serves BOTH the
	// container's address (Base32) and its inbound proxy: opening a second SAM
	// session on the same destination is rejected by I2P (DUPLICATED_DEST), so the
	// address the deployer is handed and the destination the proxy accepts on must
	// be the very same session -- otherwise every port reads closed.
	AcceptStreamPort() (net.Conn, int, error)
	Close() error
}

var base32Address = regexp.MustCompile(`^[a-z2-7]{52}\.b32\.i2p$`)

// AddressAllocator gives each container its own I2P destination.
//
// One destination per container is the whole point: a shared destination would
// mean two containers on the same worker are visibly the same host, and would
// make a private lab address impossible to keep private -- anyone who could
// reach any container could reach all of them.
type AddressAllocator struct {
	opener  SessionOpener
	dataDir string

	mu       sync.Mutex
	sessions map[string]Session
	addrs    map[string]*ContainerAddress
}

func NewAddressAllocator(opener SessionOpener, dataDir string) *AddressAllocator {
	return &AddressAllocator{
		opener:   opener,
		dataDir:  dataDir,
		sessions: map[string]Session{},
		addrs:    map[string]*ContainerAddress{},
	}
}

// keyPath is per-container and mode 0600. The key is what makes the address
// stable across a container restart: losing it would hand the container a new
// address and silently break whoever was told the old one.
func (a *AddressAllocator) keyPath(containerID string) string {
	return filepath.Join(a.dataDir, "containers", containerID, "i2p.destination")
}

// AcceptSession returns the container's already-open session as a stream accepter
// so the inbound proxy reuses the SAME destination the address came from, instead
// of opening a second session on it (which I2P rejects as a duplicate, leaving the
// address the deployer holds with nothing behind it).
func (a *AddressAllocator) AcceptSession(containerID string) (SessionAccepter, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[containerID]
	if !ok {
		return nil, false
	}
	return s, true
}

// Allocate creates (or reopens) the container's destination.
//
// private=true marks the address as never-publishable. That flag travels with
// the address rather than being re-derived at each publication site, because a
// single site that forgot to check would undo the entire containment.
func (a *AddressAllocator) Allocate(ctx context.Context, containerID string, private bool) (*ContainerAddress, error) {
	if strings.TrimSpace(containerID) == "" {
		return nil, errors.New("dcs: empty container id")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.addrs[containerID]; ok {
		return existing, nil
	}

	path := a.keyPath(containerID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("dcs: container state dir: %w", err)
	}
	session, err := a.opener.Open(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("dcs: i2p session for %s: %w", containerID, err)
	}
	// session.Base32() returns the bare 52-char destination hash; the dialable
	// address -- and what base32Address validates and the owner reaches the
	// container at -- includes the .b32.i2p suffix.
	address := session.Base32()
	if !strings.HasSuffix(address, ".b32.i2p") {
		address += ".b32.i2p"
	}
	if !base32Address.MatchString(address) {
		session.Close()
		return nil, fmt.Errorf("dcs: implausible i2p address %q", address)
	}

	entry := &ContainerAddress{ContainerID: containerID, Destination: address, Private: private}
	a.sessions[containerID] = session
	a.addrs[containerID] = entry
	return entry, nil
}

// Release closes the container's session. The key file is left in place unless
// purge is set, so a restarted container keeps its address; a destroyed one
// takes its address to the grave.
func (a *AddressAllocator) Release(containerID string, purge bool) error {
	a.mu.Lock()
	session := a.sessions[containerID]
	delete(a.sessions, containerID)
	delete(a.addrs, containerID)
	a.mu.Unlock()

	var err error
	if session != nil {
		err = session.Close()
	}
	if purge {
		// Shred-then-remove is overkill for a key whose only power is being an
		// address, but the directory also holds the disclosure record.
		if rmErr := os.RemoveAll(filepath.Dir(a.keyPath(containerID))); rmErr != nil && err == nil {
			err = rmErr
		}
	}
	return err
}

// Lookup returns a container's address entry.
func (a *AddressAllocator) Lookup(containerID string) (*ContainerAddress, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.addrs[containerID]
	return entry, ok
}

// PublishableAddresses returns only the addresses that may appear in a DHT
// service record.
//
// Every publication path MUST source its addresses here rather than iterating
// the allocator directly. That is the difference between one rule enforced once
// and a rule that has to be remembered at every call site.
func (a *AddressAllocator) PublishableAddresses() []*ContainerAddress {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*ContainerAddress
	for _, entry := range a.addrs {
		if entry.Private {
			continue
		}
		out = append(out, entry)
	}
	return out
}
