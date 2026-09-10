//go:build !linux

package dcs

import "errors"

// The container-netns bridge is Linux-only: setns(2) over /proc/<pid>/ns/net
// has no portable equivalent, and a DCS worker hosting Docker containers is a
// Linux host in practice. On other platforms the node still builds (so the
// cross-compiled release targets compile), but a worker cannot attach a
// container to its I2P destination.
var errNamespaceUnsupported = errors.New("dcs: container network namespaces are only supported on Linux")

//nolint:unused // referenced by callers on Linux; a stub on other targets.
func NewNamespaceDialer(containerPID int) (NamespaceDialer, error) {
	return nil, errNamespaceUnsupported
}
