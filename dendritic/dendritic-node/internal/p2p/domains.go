package p2p

import (
	"net/netip"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	axonpeer "github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// Failure-domain keys for shard placement — T12.2.
//
// §10's planner refuses to put two shards of one chunk in the same failure
// domain, and has done since P12b. Nothing supplied it any domains, so the
// guarantee it actually delivered was distinct-PEER — which is exactly where
// §1.4 found the storage layer, and the deficit P12b's `Domains` field was added
// to close. This file is the supplier.
//
// WHERE THE ADDRESS COMES FROM, AND WHY NOT FROM THE DHT RECORD
//
// `place.Record` carries `Destination: "<b32>.i2p"`. That is not an address in
// any sense the diversity ladder can use: an I2P destination is a public key,
// deliberately unrelated to where the machine is. §1.4's finding, in one field.
//
// A LIVE CONNECTION does expose one. libp2p hands back the remote multiaddr it
// is actually talking over, and for a TCP or QUIC transport that contains the
// peer's IP — observed by this node rather than asserted by the peer, which is
// the distinction §7.3 rule (c) turns on and the only kind of address a
// diversity claim may rest on.
//
// So domains are populated for peers reached over an IP transport and are EMPTY
// for peers reached over I2P. That is not a gap to paper over: with no
// observable address there is no observable failure domain, the planner falls
// back to distinct-peer for those candidates, and `placement.DomainsUnavailable`
// counts them so the weaker guarantee is visible rather than assumed.

// domainKeysFor returns the failure-domain keys for a connected peer, or nil.
//
// nil is a real answer and means "this node cannot observe where that peer is",
// which the planner treats as "collides with nothing" — the conservative
// direction, and the same rule `peer.SameDomain` applies to an unknown ASN.
func (n *Node) domainKeysFor(pid peer.ID) []string {
	if n == nil || n.host == nil {
		return nil
	}
	for _, conn := range n.host.Network().ConnsToPeer(pid) {
		addr, ok := ipFromMultiaddr(conn.RemoteMultiaddr())
		if !ok {
			continue
		}
		ann, err := axonpeer.Annotate(addr)
		if err != nil {
			continue
		}
		return axonpeer.DomainKeys(ann)
	}
	return nil
}

// ipFromMultiaddr extracts a routable IP from a multiaddr.
//
// Loopback and unspecified addresses are REFUSED rather than annotated. On a
// single-host test fleet every peer is 127.0.0.1, so annotating them would put
// every candidate in one /24 and the planner would refuse to place more than
// one shard — turning a diversity mechanism into an outage on exactly the setup
// people develop against. Returning nothing degrades to distinct-peer instead,
// which is the behaviour that was there before.
func ipFromMultiaddr(m ma.Multiaddr) (netip.Addr, bool) {
	if m == nil {
		return netip.Addr{}, false
	}
	ip, err := manet.ToIP(m)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}
