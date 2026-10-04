package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/circuit"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/dht"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/link"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/params"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/rendez"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
)

// A hidden service (§9.5, §9.9): it holds circuits OUT to a few intro points,
// publishes a blinded descriptor naming them, and answers each introduction by
// building a circuit to the rendezvous point the client chose. It never accepts
// an inbound connection of any kind, so it runs behind any NAT.
//
// K_svc in the rendezvous handshake is the service's identity public key: the
// one secret-free value both ends hold, the client from the address it dialled.

const serviceIntroPoints = 3

// Service is one hidden service on this node.
type Service struct {
	rt  *Runtime
	id  identity.ServiceIdentity
	lis *session.Listener

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	intros   []*introPoint
	sessions map[session.ID]*session.Session
	seen     map[[64]byte]time.Time // INTRODUCE replay cache: (auth key, X)
	rev      uint64
	dirty    chan struct{}
}

type introPoint struct {
	relay    *RelayInfo
	cc       *clientCircuit
	authPub  [32]byte
	authPriv ed25519.PrivateKey
	encPriv  [32]byte
	encPub   [32]byte
}

// Listen starts a hidden service with the given 32-byte key seed (keep it to
// keep the address) and publishes it.
func (rt *Runtime) Listen(seed [32]byte) (*Service, error) {
	id, err := identity.ServiceIdentityFromSeed(seed)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(rt.ctx)
	s := &Service{rt: rt, id: id, lis: session.NewListener(), ctx: ctx, cancel: cancel,
		sessions: map[session.ID]*session.Session{}, seen: map[[64]byte]time.Time{},
		rev: uint64(time.Now().Unix()), dirty: make(chan struct{}, 1)}
	if err := s.establishAll(); err != nil {
		cancel()
		return nil, err
	}
	if err := s.publish(); err != nil {
		rt.log.Printf("axon: service %s: first publication incomplete: %v", s.Addr(), err)
	}
	rt.mu.Lock()
	rt.services = append(rt.services, s)
	rt.mu.Unlock()
	go s.maintain()
	return s, nil
}

// Addr is the service's self-certifying address, <56 base32>.key.axon.
func (s *Service) Addr() string { return identity.FullAddress(s.id.Public) }

// Accept returns the next stream a client opened (its Meta() is what the
// client asked for, e.g. a port or protocol name).
func (s *Service) Accept() (net.Conn, error) { return s.lis.Accept() }

// Listener is the service as a net.Listener, for http.Serve and the like.
func (s *Service) Listener() net.Listener { return s.lis }

// Close stops publishing, closes the intro circuits and every session.
func (s *Service) Close() error {
	s.cancel()
	s.mu.Lock()
	intros := s.intros
	s.intros = nil
	sess := s.sessions
	s.sessions = map[session.ID]*session.Session{}
	s.mu.Unlock()
	for _, ip := range intros {
		ip.cc.close()
	}
	for _, ss := range sess {
		ss.GoAway(30 * time.Second)
		ss.Close()
	}
	return s.lis.Close()
}

func (s *Service) kSvc() [32]byte {
	var k [32]byte
	copy(k[:], s.id.Public)
	return k
}

// establishAll brings the intro point count up to serviceIntroPoints.
func (s *Service) establishAll() error {
	s.mu.Lock()
	have := map[link.NodeID]bool{}
	for _, ip := range s.intros {
		have[ip.relay.Peer] = true
	}
	need := serviceIntroPoints - len(s.intros)
	s.mu.Unlock()
	var lastErr error
	for _, ri := range s.rt.dir.Relays() {
		if need <= 0 {
			break
		}
		if have[ri.Peer] || ri.Peer == s.rt.host.ID() {
			continue
		}
		if err := s.establish(ri); err != nil {
			lastErr = err
			continue
		}
		have[ri.Peer] = true
		need--
	}
	s.mu.Lock()
	n := len(s.intros)
	s.mu.Unlock()
	if n == 0 {
		return fmt.Errorf("axon/runtime: no intro point could be established: %v", lastErr)
	}
	return nil
}

func (s *Service) establish(ri *RelayInfo) error {
	ctx, cancel := context.WithTimeout(s.ctx, 2*params.TunnelBuildTimeout)
	defer cancel()
	cc, err := s.rt.circuitTo(ctx, ri, nil)
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		cc.close()
		return err
	}
	ip := &introPoint{relay: ri, cc: cc, authPriv: priv}
	copy(ip.authPub[:], pub)
	if _, err := rand.Read(ip.encPriv[:]); err != nil {
		cc.close()
		return err
	}
	ep, err := curve25519.X25519(ip.encPriv[:], curve25519.Basepoint)
	if err != nil {
		cc.close()
		return err
	}
	copy(ip.encPub[:], ep)
	est := &rendez.EstablishIntro{AuthKey: ip.authPub,
		Sig: ed25519.Sign(priv, establishIntroMessage(ip.authPub, cc.termKeys().Af))}
	cc.mu.Lock()
	cc.onIntroduce = func(data []byte) { go s.introduced(ip, data) }
	cc.mu.Unlock()
	rep, err := cc.request(ctx, circuit.RCmdEstablishIntro, est.Encode(), circuit.RCmdIntroEstablished)
	if err != nil {
		cc.close()
		return err
	}
	ie, err := rendez.DecodeIntroEstablished(rep.Data)
	if err != nil || ie.Status != rendez.AckOK {
		cc.close()
		return errors.New("axon/runtime: intro point refused")
	}
	s.mu.Lock()
	s.intros = append(s.intros, ip)
	s.mu.Unlock()
	cc.whenDead(func() { s.introLost(ip) })
	return nil
}

func (s *Service) introLost(ip *introPoint) {
	s.mu.Lock()
	for i, x := range s.intros {
		if x == ip {
			s.intros = append(s.intros[:i], s.intros[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

// maintain replaces lost intro points (and republishes at once, since the old
// descriptor names a dead one) and republishes on the hour.
func (s *Service) maintain() {
	t := time.NewTicker(params.DescriptorRepublish)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.dirty:
			s.establishAll()
		case <-t.C:
			s.establishAll()
		}
		if err := s.publish(); err != nil {
			s.rt.log.Printf("axon: service %s: republish: %v", s.Addr(), err)
		}
	}
}

// publish writes the descriptor's replicas to their holders, for the current
// period and -- in the first half of a period -- the previous one too, so a
// client whose clock is behind still finds it (dht.PublishPlan's rule).
func (s *Service) publish() error {
	s.mu.Lock()
	var intros []introEntry
	for _, ip := range s.intros {
		intros = append(intros, introEntry{relay: ip.relay, authKey: ip.authPub, encKey: ip.encPub})
	}
	s.rev++
	rev := s.rev
	s.mu.Unlock()
	if len(intros) == 0 {
		return errors.New("axon/runtime: no intro points to publish")
	}
	now := time.Now()
	byHolder := map[link.NodeID][][2][]byte{}
	holders := map[link.NodeID]*RelayInfo{}
	for _, period := range dht.FetchPeriods(now) {
		signer, err := identity.BlindSigner(s.id.PrivateKey(), period)
		if err != nil {
			return err
		}
		blinded := []byte(signer.Public().(ed25519.PublicKey))
		subcred := identity.Subcredential(s.id.Public, identity.BlindedPub(blinded))
		inner, err := sealInner(blinded, period, subcred, intros)
		if err != nil {
			return err
		}
		for j := uint8(0); j < dht.DescriptorReplicaPositions; j++ {
			d := &dht.ServiceDescriptor{Ver: 1, BlindedPub: blinded, TimePeriod: period, ReplicaIndex: j,
				Revision: rev, IssuedAt: now.Unix(), ExpiresAt: now.Add(params.DescriptorLifetime).Unix(),
				Inner: inner}
			if err := d.SignWith(signer.SignMessage); err != nil {
				return err
			}
			wire, err := dht.Encode(d)
			if err != nil {
				return err
			}
			key, err := d.DerivedKey()
			if err != nil {
				return err
			}
			for _, h := range s.rt.dir.Closest(key, s.rt.dir.hsdirReplicas()) {
				holders[h.Peer] = h
				byHolder[h.Peer] = append(byHolder[h.Peer], [2][]byte{key[:], wire})
			}
		}
	}
	var failed int
	for id, items := range byHolder {
		if err := s.storeAt(holders[id], items); err != nil {
			failed++
		}
	}
	if failed == len(byHolder) {
		return errors.New("axon/runtime: no descriptor holder accepted the descriptor")
	}
	return nil
}

func (s *Service) storeAt(h *RelayInfo, items [][2][]byte) error {
	ctx, cancel := context.WithTimeout(s.ctx, 3*params.TunnelBuildTimeout)
	defer cancel()
	cc, err := s.rt.circuitTo(ctx, h, nil)
	if err != nil {
		return err
	}
	defer cc.close()
	ctl := cc.control()
	defer ctl.Close()
	for _, it := range items {
		var key dht.Key
		copy(key[:], it[0])
		if err := hsdirStoreAt(ctx, ctl, key, it[1]); err != nil {
			return err
		}
	}
	return nil
}

// introduced answers one INTRODUCE2.
func (s *Service) introduced(ip *introPoint, data []byte) {
	m, verdict, err := decodeIntroduce2(data)
	if err != nil || verdict != rendez.AckOK {
		return
	}
	var rk [64]byte
	copy(rk[:32], ip.authPub[:])
	copy(rk[32:], m.X[:])
	s.mu.Lock()
	if _, dup := s.seen[rk]; dup {
		s.mu.Unlock()
		return // a replayed introduction costs nothing past this point
	}
	now := time.Now()
	s.seen[rk] = now
	for k, t := range s.seen {
		if now.Sub(t) > params.DescriptorLifetime {
			delete(s.seen, k)
		}
	}
	s.mu.Unlock()

	// The client sealed it under the subcredential of ITS current period; ours
	// may differ by one at a boundary.
	var pt *rendez.IntroPlaintext
	for _, period := range []uint64{identity.PeriodNumber(now), identity.PeriodNumber(now) - 1, identity.PeriodNumber(now) + 1} {
		blinded, subcred, err := blindedFor(s.id.Public, period)
		if err != nil {
			continue
		}
		_ = blinded
		if p, err := rendez.OpenIntro(ip.encPriv, ip.encPub, s.kSvc(), subcred, m); err == nil {
			pt = p
			break
		}
	}
	if pt == nil {
		return
	}
	rp := s.rt.dir.ByStaticID(pt.RPRoutingID)
	if rp == nil {
		return // a rendezvous point this node cannot reach
	}
	seed, hs, err := rendez.ServiceRendezvous(rand.Reader, ip.encPriv, ip.encPub, s.kSvc(), m.X)
	if err != nil {
		return
	}
	id := session.ID(pt.SessionID)
	var sess *session.Session
	if pt.ResumePresent {
		s.mu.Lock()
		sess = s.sessions[id]
		s.mu.Unlock()
		if sess == nil {
			return
		}
		if err := sess.AcceptResume(pt.SessionCtr, pt.SessionProof, pt.Cookie, pt.RPRoutingID); err != nil {
			return
		}
		if err := sess.Ratchet(seed); err != nil {
			return
		}
	} else {
		cfg := s.rt.cfg.Session
		cfg.OnClose = func(ss *session.Session, _ error) {
			s.mu.Lock()
			if s.sessions[ss.ID()] == ss {
				delete(s.sessions, ss.ID())
			}
			s.mu.Unlock()
		}
		sess = session.NewService(seed, id, cfg)
		s.mu.Lock()
		if s.sessions[id] != nil {
			s.mu.Unlock()
			sess.Close()
			return
		}
		s.sessions[id] = sess
		s.mu.Unlock()
		s.lis.Serve(sess)
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*params.TunnelBuildTimeout)
	defer cancel()
	cc, err := s.rt.circuitTo(ctx, rp, nil)
	if err != nil {
		return
	}
	// Listen first, announce second: the client's first packets may arrive the
	// moment the RP splices, but nothing of ours may reach the RP before the
	// RENDEZVOUS1 that makes it a splice rather than a control session.
	k := cc.receiveInto(sess)
	if err := cc.send(circuit.RCmdRendezvous1, (&rendez.Rendezvous1{Cookie: pt.Cookie, HS: hs}).Encode()); err != nil {
		cc.close()
		return
	}
	sess.Attach(k)
}
