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

// SessionOpener starts a container's AXON hidden service from a key file,
// returning something that knows its own address. The node supplies one over
// its overlay runtime; the interface keeps the allocator testable without an
// overlay.
type SessionOpener interface {
	Open(ctx context.Context, keyPath string) (Session, error)
}

type Session interface {
	// Address is the service's AXON address, <56 base32>.key.axon.
	Address() string
	// AcceptStreamPort accepts an inbound stream on this service and reports
	// the port the caller dialed. It is here so ONE session serves BOTH the
	// container's address and its inbound proxy: the address the deployer is
	// handed and the service the proxy accepts on must be the very same one --
	// a second service on the same key would split the intro points between
	// two publishers, and every port would read closed half the time.
	AcceptStreamPort() (net.Conn, int, error)
	Close() error
}

var overlayAddress = regexp.MustCompile(`^[a-z2-7]{56}\.key\.axon$`)

// AddressAllocator gives each container its own AXON address.
//
// One address per container is the whole point: a shared address would
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
	return filepath.Join(a.dataDir, "containers", containerID, "axon.service.key")
}

// AcceptSession returns the container's already-open session as a stream accepter
// so the inbound proxy reuses the SAME service the address came from, instead of
// starting a second one on it (leaving the address the deployer holds with a
// rival publisher behind it).
func (a *AddressAllocator) AcceptSession(containerID string) (SessionAccepter, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[containerID]
	if !ok {
		return nil, false
	}
	return s, true
}

// Allocate creates (or reopens) the container's address.
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
		return nil, fmt.Errorf("dcs: AXON service for %s: %w", containerID, err)
	}
	// The dialable address -- what overlayAddress validates and the owner
	// reaches the container at -- is the full <56>.key.axon form.
	address := session.Address()
	if !strings.HasSuffix(address, ".key.axon") {
		address += ".key.axon"
	}
	if !overlayAddress.MatchString(address) {
		session.Close()
		return nil, fmt.Errorf("dcs: implausible AXON address %q", address)
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
