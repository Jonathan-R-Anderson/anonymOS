package runtime

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
	"github.com/syndichan/maniwani/storage-client/internal/axon/dht"
	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
)

// The relay directory: every relay's self-signed RelayDescriptor (the dht
// record), verified by the dht Validator, exchanged between relays and fetched
// by clients.
//
// A descriptor binds a relay's link identity (NodeIdentity, which the libp2p
// handshake proves) to its routing keys (which the ntor handshake proves) and
// its addresses. Nothing in it is trusted further than that: a relay can lie
// about its bandwidth, not about who it is.

// DirProtocol is the libp2p protocol the directory is exchanged on.
const DirProtocol = protocol.ID("/axon/dir/1.0.0")

const (
	dirMaxRelays    = 8192
	dirRefresh      = 10 * time.Minute
	descriptorLife  = 3 * time.Hour // dht.TTLRelayDescriptor
	capRelay        = 1 << 0
	dirStreamTimout = 20 * time.Second
)

// RelayInfo is a verified relay.
type RelayInfo struct {
	Peer    link.NodeID
	NodePub ed25519.PublicKey
	Static  circuit.RelayStatic
	Addrs   []string // "ip:port"; TCP and QUIC on the same port
	Seq     uint64
	Expires time.Time
	wire    []byte
}

// Multiaddrs are the link addresses of the relay.
func (ri *RelayInfo) Multiaddrs() []ma.Multiaddr {
	var out []ma.Multiaddr
	for _, a := range ri.Addrs {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			continue
		}
		fam := "ip4"
		if ap.Addr().Is6() {
			fam = "ip6"
		}
		for _, s := range []string{
			fmt.Sprintf("/%s/%s/tcp/%d", fam, ap.Addr(), ap.Port()),
			fmt.Sprintf("/%s/%s/udp/%d/quic-v1", fam, ap.Addr(), ap.Port()),
		} {
			if m, err := ma.NewMultiaddr(s); err == nil {
				out = append(out, m)
			}
		}
	}
	return out
}

// prefix is the relay's /16 (or /32 for v6): two relays in one prefix are, for
// path diversity, one relay.
func (ri *RelayInfo) prefix() string {
	for _, a := range ri.Addrs {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			continue
		}
		bits := 16
		if ap.Addr().Is6() {
			bits = 32
		}
		p, _ := ap.Addr().Prefix(bits)
		return p.String()
	}
	return ""
}

// ringID is where the relay sits for hidden-service descriptor placement.
func (ri *RelayInfo) ringID() [32]byte { return sha256.Sum256(ri.NodePub) }

// Directory is the set of relays this node knows.
type Directory struct {
	rt    *Runtime
	v     *dht.Validator
	mu    sync.Mutex
	known map[link.NodeID]*RelayInfo
	self  *RelayInfo
}

func newDirectory(rt *Runtime) *Directory {
	return &Directory{rt: rt, v: &dht.Validator{Now: time.Now}, known: map[link.NodeID]*RelayInfo{}}
}

// Add verifies a descriptor and keeps it if it is new or newer.
func (d *Directory) Add(wire []byte) (*RelayInfo, error) {
	rec, err := dht.DecodeRecord(dht.ClassRelay, wire)
	if err != nil {
		return nil, err
	}
	rd, ok := rec.(*dht.RelayDescriptor)
	if !ok {
		return nil, errors.New("axon/runtime: not a relay descriptor")
	}
	key, err := rd.DerivedKey()
	if err != nil {
		return nil, err
	}
	if _, err := d.v.Validate(dht.ClassRelay, key, wire); err != nil {
		return nil, err
	}
	if len(rd.RoutingEd) != 32 || len(rd.RoutingX) != 32 || len(rd.Addrs) == 0 {
		return nil, errors.New("axon/runtime: relay descriptor lacks routing keys or addresses")
	}
	id, err := link.NodeIDFromPublic(ed25519.PublicKey(rd.NodeIDPub))
	if err != nil {
		return nil, err
	}
	ri := &RelayInfo{Peer: id, NodePub: ed25519.PublicKey(append([]byte(nil), rd.NodeIDPub...)),
		Addrs: append([]string(nil), rd.Addrs...), Seq: rd.Sequence,
		Expires: time.Unix(rd.ExpiresAt, 0), wire: append([]byte(nil), wire...)}
	copy(ri.Static.RID[:], rd.RoutingEd)
	copy(ri.Static.B[:], rd.RoutingX)
	ri.Static.Epoch = rd.Epoch
	d.mu.Lock()
	defer d.mu.Unlock()
	if prev, ok := d.known[id]; ok && prev.Seq >= ri.Seq {
		return prev, nil
	}
	if _, ok := d.known[id]; !ok && len(d.known) >= dirMaxRelays {
		return nil, errors.New("axon/runtime: directory full")
	}
	d.known[id] = ri
	return ri, nil
}

// Relays lists the live relays, in a stable order.
func (d *Directory) Relays() []*RelayInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	out := make([]*RelayInfo, 0, len(d.known))
	for id, ri := range d.known {
		if now.After(ri.Expires) {
			delete(d.known, id)
			continue
		}
		out = append(out, ri)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Peer < out[j].Peer })
	return out
}

// ByStaticID finds a relay by its EXTEND identifier, SHA256(RID).
func (d *Directory) ByStaticID(id [32]byte) *RelayInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ri := range d.known {
		if ri.Static.ID() == id {
			return ri
		}
	}
	return nil
}

// Closest are the n relays nearest key on the ring -- a descriptor's holders.
func (d *Directory) Closest(key [32]byte, n int) []*RelayInfo {
	all := d.Relays()
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i].ringID(), all[j].ringID()
		for k := 0; k < 32; k++ {
			x, y := a[k]^key[k], b[k]^key[k]
			if x != y {
				return x < y
			}
		}
		return false
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// announceAddrs is what this relay publishes.
func (d *Directory) announceAddrs() []string {
	if len(d.rt.cfg.Announce) > 0 {
		return d.rt.cfg.Announce
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range d.rt.host.Addrs() {
		na, err := manet.ToNetAddr(a)
		if err != nil {
			continue
		}
		tcp, ok := na.(*net.TCPAddr)
		if !ok {
			continue
		}
		s := net.JoinHostPort(tcp.IP.String(), strconv.Itoa(tcp.Port))
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// publishSelf signs and adds this relay's descriptor.
func (d *Directory) publishSelf() error {
	now := time.Now()
	rt := d.rt
	rd := &dht.RelayDescriptor{
		Ver:       1,
		NodeIDPub: append([]byte(nil), rt.node.Public...),
		RoutingEd: append([]byte(nil), rt.routing.EdPublic...),
		RoutingX:  append([]byte(nil), rt.routing.XPublic[:]...),
		Addrs:     d.announceAddrs(),
		Caps:      capRelay,
		Epoch:     rt.routing.Epoch,
		SRVEpoch:  directoryEpochTag(rt.routing.Epoch),
		Sequence:  uint64(now.UnixNano()),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(descriptorLife).Unix(),
	}
	if len(rd.Addrs) == 0 {
		return errors.New("axon/runtime: relay has no address to announce")
	}
	if err := rd.Sign(rt.node.PrivateKey()); err != nil {
		return err
	}
	wire, err := dht.Encode(rd)
	if err != nil {
		return err
	}
	ri, err := d.Add(wire)
	if err != nil {
		return fmt.Errorf("axon/runtime: own descriptor refused: %w", err)
	}
	d.mu.Lock()
	d.self = ri
	d.mu.Unlock()
	return nil
}

// directoryEpochTag fills the descriptor's SRV_epoch field. That field is §5.4's
// shared random value, which positions a node in the DHT keyspace; no source of
// it is wired yet (dht.SRVSource has no production implementation) and the
// directory does not place relays by KadID, so this is a deterministic per-epoch
// tag, NOT a random value -- nothing may treat it as one.
func directoryEpochTag(epoch uint64) []byte {
	h := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("axon:directory-epoch:v1"), epoch))
	return h[:]
}

// Self is this relay's own entry (nil for a client).
func (d *Directory) Self() *RelayInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.self
}

// ---------------------------------------------------------------- exchange

// The protocol: one request per stream.
//
//	'F'                       -> count u32 ‖ (len u32 ‖ wire)*
//	'P' count u32 ‖ (len u32 ‖ wire)*  -> 'K'
func writeWires(w io.Writer, wires [][]byte) error {
	bw := bufio.NewWriter(w)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(wires)))
	bw.Write(n[:])
	for _, x := range wires {
		binary.BigEndian.PutUint32(n[:], uint32(len(x)))
		bw.Write(n[:])
		bw.Write(x)
	}
	return bw.Flush()
}

func readWires(r io.Reader) ([][]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(n[:])
	if count > dirMaxRelays {
		return nil, errors.New("axon/runtime: directory too large")
	}
	out := make([][]byte, 0, count)
	for i := uint32(0); i < count; i++ {
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return nil, err
		}
		l := binary.BigEndian.Uint32(n[:])
		if l > dht.MaxRelayDescriptor {
			return nil, errors.New("axon/runtime: descriptor too large")
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (d *Directory) wires() [][]byte {
	var out [][]byte
	for _, ri := range d.Relays() {
		out = append(out, ri.wire)
	}
	return out
}

func (d *Directory) serve() {
	d.rt.host.SetStreamHandler(DirProtocol, func(s network.Stream) {
		defer s.Close()
		s.SetDeadline(time.Now().Add(dirStreamTimout))
		var op [1]byte
		if _, err := io.ReadFull(s, op[:]); err != nil {
			s.Reset()
			return
		}
		switch op[0] {
		case 'F':
			_ = writeWires(s, d.wires())
		case 'P':
			wires, err := readWires(s)
			if err != nil {
				s.Reset()
				return
			}
			for _, w := range wires {
				d.Add(w)
			}
			s.Write([]byte{'K'})
		default:
			s.Reset()
		}
	})
}

// exchange pushes this relay's descriptor (if any) to a peer and pulls the
// peer's directory.
func (d *Directory) exchange(ctx context.Context, addr string) error {
	ai, err := parsePeerAddr(addr)
	if err != nil {
		return err
	}
	if ai.ID == d.rt.host.ID() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dirStreamTimout)
	defer cancel()
	if err := d.rt.host.Connect(ctx, ai); err != nil {
		return err
	}
	if self := d.Self(); self != nil {
		s, err := d.rt.host.NewStream(ctx, ai.ID, DirProtocol)
		if err != nil {
			return err
		}
		s.Write([]byte{'P'})
		writeWires(s, [][]byte{self.wire})
		var k [1]byte
		io.ReadFull(s, k[:])
		s.Close()
	}
	s, err := d.rt.host.NewStream(ctx, ai.ID, DirProtocol)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Write([]byte{'F'}); err != nil {
		return err
	}
	wires, err := readWires(s)
	if err != nil {
		return err
	}
	for _, w := range wires {
		d.Add(w)
	}
	return nil
}

// bootstrap reaches the seeds. A client with no reachable seed has no network.
func (d *Directory) bootstrap(ctx context.Context) error {
	if len(d.rt.cfg.Seeds) == 0 {
		if d.rt.cfg.Relay {
			return nil
		}
		return errors.New("axon/runtime: no seeds to fetch the relay directory from")
	}
	var last error
	ok := 0
	for _, s := range d.rt.cfg.Seeds {
		if err := d.exchange(ctx, s); err != nil {
			last = err
			continue
		}
		ok++
	}
	if ok == 0 {
		return fmt.Errorf("axon/runtime: no seed answered: %w", last)
	}
	return nil
}

// Refresh re-runs the exchange now: republish (relays), then pull from the
// seeds and from every relay already known.
func (d *Directory) Refresh(ctx context.Context) {
	if d.rt.cfg.Relay {
		d.publishSelf()
	}
	for _, s := range d.rt.cfg.Seeds {
		d.exchange(ctx, s)
	}
	if d.rt.cfg.Relay {
		for _, ri := range d.Relays() {
			for _, m := range ri.Multiaddrs() {
				if d.exchange(ctx, m.String()+"/p2p/"+ri.Peer.String()) == nil {
					break
				}
			}
		}
	}
}

func (d *Directory) maintain() {
	t := time.NewTicker(dirRefresh)
	defer t.Stop()
	for {
		select {
		case <-d.rt.ctx.Done():
			return
		case <-t.C:
			d.Refresh(d.rt.ctx)
		}
	}
}
