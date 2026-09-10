package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	natpmp "github.com/jackpal/go-nat-pmp"

	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

// Real mapping backends over the already-vendored goupnp and go-nat-pmp.
//
// Neither is constructed unless MappingConfig.Enabled is set: discovery itself
// broadcasts on the local network, and a node that probes the operator's router
// without being asked has already done the thing §6.5 forbids.

// MappingDescription is what the router shows the operator in its UI. It names
// the software so somebody auditing their router can tell what asked.
const MappingDescription = "AXON node"

// upnpMapper maps over UPnP-IGD, trying IGDv2 before IGDv1.
type upnpMapper struct {
	client upnpClient
}

// upnpClient is the slice of the goupnp WANIPConnection interface we use. Both
// generated v1 and v2 clients satisfy it.
type upnpClient interface {
	AddPortMapping(NewRemoteHost string, NewExternalPort uint16, NewProtocol string,
		NewInternalPort uint16, NewInternalClient string, NewEnabled bool,
		NewPortMappingDescription string, NewLeaseDuration uint32) error
	DeletePortMapping(NewRemoteHost string, NewExternalPort uint16, NewProtocol string) error
	GetExternalIPAddress() (NewExternalIPAddress string, err error)
}

// NewUPnPMapper discovers an IGD on the local network.
//
// It is an error to call this without operator opt-in; the caller is
// MappingManager, which checks Enabled first.
func NewUPnPMapper(ctx context.Context) (Mapper, error) {
	if v2, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil && len(v2) > 0 {
		return &upnpMapper{client: v2[0]}, nil
	}
	if v2, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil && len(v2) > 0 {
		return &upnpMapper{client: v2[0]}, nil
	}
	v1, _, err := internetgateway1.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("axon/peer: UPnP discovery: %w", err)
	}
	if len(v1) == 0 {
		return nil, errors.New("axon/peer: no UPnP-IGD device found")
	}
	return &upnpMapper{client: v1[0]}, nil
}

func (u *upnpMapper) Protocol() MappingProtocol { return MappingUPnP }

func (u *upnpMapper) Map(ctx context.Context, internalPort uint16, lease time.Duration) (Mapping, error) {
	local, err := localAddrFor(ctx)
	if err != nil {
		return Mapping{}, err
	}
	secs := uint32(lease / time.Second)

	// Request the same external port as the internal one. UPnP has no "any
	// port" request that is portable across implementations, and a stable
	// external port is what makes the halfway refresh a renewal rather than a
	// new hole beside the old one.
	if err := u.client.AddPortMapping("", internalPort, "UDP", internalPort,
		local.String(), true, MappingDescription, secs); err != nil {
		return Mapping{}, fmt.Errorf("axon/peer: UPnP AddPortMapping: %w", err)
	}

	m := Mapping{
		Protocol: MappingUPnP, InternalPort: internalPort,
		ExternalPort: internalPort, Lease: lease,
	}
	// The external address the IGD reports is a HINT. §6.5 step QUORUM still
	// requires >=3 diverse peers to agree before anything is advertised, and
	// this value never bypasses that.
	if ip, err := u.client.GetExternalIPAddress(); err == nil {
		if addr, err := netip.ParseAddr(ip); err == nil {
			m.External = addr
		}
	}
	return m, nil
}

func (u *upnpMapper) Unmap(_ context.Context, m Mapping) error {
	return u.client.DeletePortMapping("", m.ExternalPort, "UDP")
}

// natpmpMapper maps over NAT-PMP, which PCP-capable gateways also answer.
type natpmpMapper struct {
	client *natpmp.Client
}

// NewNATPMPMapper builds a client against the default gateway.
func NewNATPMPMapper(gateway netip.Addr) (Mapper, error) {
	if !gateway.IsValid() {
		return nil, errors.New("axon/peer: NAT-PMP needs a gateway address")
	}
	return &natpmpMapper{
		client: natpmp.NewClientWithTimeout(net.IP(gateway.AsSlice()), 5*time.Second),
	}, nil
}

func (n *natpmpMapper) Protocol() MappingProtocol { return MappingNATPMP }

func (n *natpmpMapper) Map(_ context.Context, internalPort uint16, lease time.Duration) (Mapping, error) {
	res, err := n.client.AddPortMapping("udp", int(internalPort), int(internalPort), int(lease/time.Second))
	if err != nil {
		return Mapping{}, fmt.Errorf("axon/peer: NAT-PMP AddPortMapping: %w", err)
	}
	m := Mapping{
		Protocol:     MappingNATPMP,
		InternalPort: internalPort,
		ExternalPort: res.MappedExternalPort,
		// The gateway's granted lifetime, which may be shorter than requested.
		// Using the GRANTED value is what keeps the halfway refresh inside the
		// window the router actually promised.
		Lease: time.Duration(res.PortMappingLifetimeInSeconds) * time.Second,
	}
	if m.Lease <= 0 {
		m.Lease = lease
	}
	if ext, err := n.client.GetExternalAddress(); err == nil {
		if addr, ok := netip.AddrFromSlice(ext.ExternalIPAddress[:]); ok {
			m.External = addr
		}
	}
	return m, nil
}

func (n *natpmpMapper) Unmap(_ context.Context, m Mapping) error {
	// A lifetime of zero is NAT-PMP's delete.
	_, err := n.client.AddPortMapping("udp", int(m.InternalPort), 0, 0)
	return err
}

// localAddrFor returns this host's address on the route towards the default
// gateway. It opens no connection -- a UDP "dial" only selects a route.
func localAddrFor(ctx context.Context) (netip.Addr, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", "192.0.2.1:9")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("axon/peer: local address: %w", err)
	}
	defer c.Close()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

// NewMappersFor builds the mappers named by a config, in the config's order.
//
// IT EXISTS BECAUSE THE ORDER WAS DEAD CONFIG. MappingConfig.protocols() has
// always returned a preference order and nothing turned it into mappers:
// NewMappingManager takes them as a variadic argument and every caller passed
// its own. So "UPnP, then PCP, then NAT-PMP" described an intention no code
// carried out, and adding PCP to that list would otherwise have implemented a
// protocol nothing could reach.
//
// SEPARATE AND STILL OPEN: nothing in cmd/ calls this, or NewMappingManager, at
// all. Port mapping is off by default (§6.5) and this makes it constructible;
// it does not make it wired. That gap is not F3's and is not closed here.
//
// A protocol whose discovery fails is SKIPPED, not fatal: a gateway speaking
// PCP but not UPnP is the ordinary case, and refusing to map at all because the
// first choice was absent would make the preference order a requirement list.
func NewMappersFor(ctx context.Context, cfg MappingConfig) ([]Mapper, error) {
	if !cfg.Enabled {
		// The opt-in check lives here as well as in the manager, because this
		// function performs DISCOVERY -- UPnP discovery broadcasts on the local
		// network, and doing that unasked is the thing §6.5 forbids.
		return nil, ErrMappingDisabled
	}
	var (
		out   []Mapper
		local netip.Addr
		errs  []error
	)
	for _, proto := range cfg.protocols() {
		switch proto {
		case MappingUPnP:
			m, err := NewUPnPMapper(ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("upnp: %w", err))
				continue
			}
			out = append(out, m)
		case MappingPCP, MappingNATPMP:
			// Both need the default gateway and this node's address on the
			// route to it; found once and shared.
			if !local.IsValid() {
				a, err := localAddrFor(ctx)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", proto, err))
					continue
				}
				local = a
			}
			gw, err := defaultGateway(ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", proto, err))
				continue
			}
			var m Mapper
			if proto == MappingPCP {
				m, err = NewPCPMapper(gw, local)
			} else {
				m, err = NewNATPMPMapper(gw)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", proto, err))
				continue
			}
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrNoMapper, errors.Join(errs...))
	}
	return out, nil
}

// defaultGateway reads the default route's next hop from /proc/net/route.
//
// IT DOES NOT GUESS. The obvious shortcut is to assume the gateway is the .1 of
// the local /24, and it is wrong often enough to matter -- on networks numbered
// from .254, on point-to-point links, and on anything with more than one subnet.
// A wrong guess does not fail cleanly: it sends PCP requests to whatever
// unrelated host happens to hold that address, which is a mapping attempt
// against a machine that never consented to one. An error is the correct
// outcome when the route cannot be read.
//
// Linux only. On other platforms this returns an error and the PCP and NAT-PMP
// backends are skipped, which is honest: the node still maps over UPnP if the
// operator opted in, and reports why the others were not attempted.
func defaultGateway(ctx context.Context) (netip.Addr, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("axon/peer: default gateway: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		// Destination 00000000 is the default route.
		if f[1] != "00000000" {
			continue
		}
		// The next hop is little-endian hex, which is the one detail that makes
		// this worth a comment: 0101A8C0 is 192.168.1.1, not 1.1.168.192.
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		gw := netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
		if gw.IsUnspecified() {
			continue
		}
		return gw, nil
	}
	return netip.Addr{}, errors.New("axon/peer: no default route with a next hop")
}
