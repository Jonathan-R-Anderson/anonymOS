package dcs

import (
	"context"
	"fmt"
)

// ContainerSessionFactory opens a NEW I2P destination for a container. In
// production this is a closure over internal/i2p.Open bound to the container's
// own key file (one destination per container, address.go). It is an interface
// so the attacher is testable without a SAM bridge.
type ContainerSessionFactory interface {
	// OpenForContainer returns a session listening on the container's own
	// destination.
	OpenForContainer(ctx context.Context, containerID string) (SessionAccepter, error)
}

// ContainerPIDResolver returns a container's main process PID, from
// `docker inspect`. *DockerClient will grow an InspectPID; the interface keeps
// the attacher decoupled from Docker for tests.
type ContainerPIDResolver interface {
	ContainerPID(ctx context.Context, containerID string) (int, error)
}

// NamespaceDialerFactory builds the netns dialer for a PID. In production this
// is NewNamespaceDialer (Linux); tests supply an in-process dialer.
type NamespaceDialerFactory func(pid int) (NamespaceDialer, error)

// productionAttacher is the real NetworkAttacher: it opens the container's
// destination, resolves its PID, builds the netns dialer, and runs the proxy.
type productionAttacher struct {
	sessions ContainerSessionFactory
	pids     ContainerPIDResolver
	dialer   NamespaceDialerFactory
	logf     func(string, ...any)
}

// NewNetworkAttacher assembles the production attacher. Any nil dependency
// disables attachment cleanly (the agent then returns the address unbridged
// and says so) rather than panicking mid-launch.
func NewNetworkAttacher(sessions ContainerSessionFactory, pids ContainerPIDResolver, dialer NamespaceDialerFactory, logf func(string, ...any)) NetworkAttacher {
	if dialer == nil {
		dialer = NewNamespaceDialer
	}
	return &productionAttacher{sessions: sessions, pids: pids, dialer: dialer, logf: logf}
}

func (p *productionAttacher) Attach(ctx context.Context, containerID string, primaryPort int) (NetworkHandle, error) {
	if p.sessions == nil || p.pids == nil {
		return nil, fmt.Errorf("dcs: network attachment is not configured on this host")
	}
	session, err := p.sessions.OpenForContainer(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("open container destination: %w", err)
	}
	pid, err := p.pids.ContainerPID(ctx, containerID)
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("resolve container pid: %w", err)
	}
	dialer, err := p.dialer(pid)
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("enter container netns: %w", err)
	}

	network := &ContainerNetwork{}
	network.AttachInbound(containerID, NewSessionListener(session), dialer, primaryPort, p.logf)
	return &networkHandle{network: network}, nil
}

type networkHandle struct{ network *ContainerNetwork }

func (h *networkHandle) Detach() { h.network.Detach() }
