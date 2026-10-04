package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/circuit"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/dht"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/link"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/params"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/rendez"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
)

// Connecting to a service (§9.5, client side): fetch its descriptor through a
// circuit, pick a rendezvous point, introduce through one of its intro points,
// complete the handshake, and run a session on the joined circuit. One session
// per destination is kept and reused; every Dial is a stream on it.
//
// When the circuit under the session dies the session orphans and this file
// rebuilds it: case A first (a fresh circuit to the same RP, which held the
// service's side), case B if the RP refuses or is gone (a new RP and a new
// introduction carrying the session's resume proof, then a ratchet).

var (
	ErrNoDescriptor = errors.New("axon/runtime: no descriptor found for that address")
	ErrIntroRefused = errors.New("axon/runtime: every intro point refused the introduction")
)

// remote is this node's session with one destination.
type remote struct {
	rt      *Runtime
	addr    string
	pub     ed25519.PublicKey
	mu      sync.Mutex
	sess    *session.Session
	rp      *RelayInfo
	rendCC  *clientCircuit
	intros  []introEntry
	ready   chan struct{}
	err     error
	closing bool
}

// Dial opens a stream to a service. addr is "<56 base32>.key.axon"; meta is
// what the service sees as the stream's purpose (a port, a protocol name).
func (rt *Runtime) Dial(ctx context.Context, addr string, meta []byte) (net.Conn, error) {
	r, err := rt.remoteFor(ctx, addr)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	s := r.sess
	r.mu.Unlock()
	return s.OpenStream(meta)
}

// DialContext is Dial in the shape net/http wants: "host:port" with host an
// AXON address; the port becomes the stream's metadata.
func (rt *Runtime) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, ""
	}
	return rt.Dial(ctx, host, []byte(port))
}

func (rt *Runtime) remoteFor(ctx context.Context, addr string) (*remote, error) {
	pub, err := identity.ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(identity.FullAddress(pub))
	rt.mu.Lock()
	r := rt.dials[key]
	if r != nil {
		r.mu.Lock()
		dead := r.sess != nil && r.sess.State() == session.Closed
		failed := r.err != nil && r.ready != nil && isClosed(r.ready)
		r.mu.Unlock()
		if dead || failed {
			delete(rt.dials, key)
			r = nil
		}
	}
	if r == nil {
		r = &remote{rt: rt, addr: key, pub: pub, ready: make(chan struct{})}
		rt.dials[key] = r
		go func() {
			err := r.connect(rt.ctx)
			r.mu.Lock()
			r.err = err
			r.mu.Unlock()
			close(r.ready)
		}()
	}
	rt.mu.Unlock()
	select {
	case <-r.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	return r, nil
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (r *remote) close() {
	r.mu.Lock()
	r.closing = true
	s, cc := r.sess, r.rendCC
	r.mu.Unlock()
	if s != nil {
		s.Close()
	}
	if cc != nil {
		cc.close()
	}
}

func (r *remote) kSvc() [32]byte {
	var k [32]byte
	copy(k[:], r.pub)
	return k
}

// fetchDescriptor finds and opens the service's descriptor: current period
// first, then (in the overlap) the previous; replicas in random order; each
// replica's holders in ring order.
func (r *remote) fetchDescriptor(ctx context.Context) ([]introEntry, error) {
	rt := r.rt
	for _, period := range dht.FetchPeriods(time.Now()) {
		blinded, subcred, err := blindedFor(r.pub, period)
		if err != nil {
			return nil, err
		}
		for _, j := range mrand.Perm(int(dht.DescriptorReplicaPositions)) {
			key, err := descriptorKey(blinded, period, uint8(j))
			if err != nil {
				return nil, err
			}
			for _, h := range rt.dir.Closest(key, rt.dir.hsdirReplicas()) {
				wire, err := rt.fetchFrom(ctx, h, key)
				if err != nil || len(wire) == 0 {
					continue
				}
				v := dht.Validator{Now: time.Now}
				rec, err := v.Validate(dht.ClassDesc, key, wire)
				if err != nil {
					continue
				}
				d := rec.(*dht.ServiceDescriptor)
				intros, err := rt.dir.openInner(blinded, period, subcred, d.Inner)
				if err != nil || len(intros) == 0 {
					continue
				}
				return intros, nil
			}
		}
	}
	return nil, ErrNoDescriptor
}

func (rt *Runtime) fetchFrom(ctx context.Context, h *RelayInfo, key dht.Key) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*params.TunnelBuildTimeout)
	defer cancel()
	cc, err := rt.circuitTo(cctx, h, nil)
	if err != nil {
		return nil, err
	}
	defer cc.close()
	ctl := cc.control()
	defer ctl.Close()
	return hsdirFetchAt(cctx, ctl, key)
}

// rendezvous sets up a rendezvous point and returns its circuit, cookie and the
// channel RENDEZVOUS2 will arrive on.
func (r *remote) rendezvous(ctx context.Context, avoid map[link.NodeID]bool) (*RelayInfo, *clientCircuit, rendez.Cookie, chan *circuit.RelayCell, error) {
	var cookie rendez.Cookie
	var cands []*RelayInfo
	for _, ri := range r.rt.dir.Relays() {
		if !avoid[ri.Peer] && ri.Peer != r.rt.host.ID() {
			cands = append(cands, ri)
		}
	}
	if len(cands) == 0 {
		return nil, nil, cookie, nil, ErrTooFewRelay
	}
	rp := cands[mrand.IntN(len(cands))]
	cc, err := r.rt.circuitTo(ctx, rp, nil)
	if err != nil {
		return nil, nil, cookie, nil, err
	}
	cookie, err = rendez.NewCookie(rand.Reader)
	if err != nil {
		cc.close()
		return nil, nil, cookie, nil, err
	}
	r2 := cc.expect(circuit.RCmdRendezvous2)
	rep, err := cc.request(ctx, circuit.RCmdEstablishRendezvous, (&rendez.EstablishRendezvous{Cookie: cookie}).Encode(),
		circuit.RCmdRendezvousEstablished)
	if err != nil || len(rep.Data) < 1 || rep.Data[0] != 0 {
		cc.close()
		return nil, nil, cookie, nil, fmt.Errorf("axon/runtime: rendezvous point refused: %v", err)
	}
	return rp, cc, cookie, r2, nil
}

// introduce sends INTRODUCE1 through one intro point after another until one
// admits it; it returns the client's ephemeral and the intro used.
func (r *remote) introduce(ctx context.Context, pt *rendez.IntroPlaintext) ([32]byte, *introEntry, *rendez.Introduce1, error) {
	blinded, subcred, err := blindedFor(r.pub, identity.PeriodNumber(time.Now()))
	if err != nil {
		return [32]byte{}, nil, nil, err
	}
	_ = blinded
	order := mrand.Perm(len(r.intros))
	for _, i := range order {
		ip := &r.intros[i]
		m, x, err := rendez.SealIntro(rand.Reader, ip.encKey, r.kSvc(), ip.authKey, subcred, pt, nil)
		if err != nil {
			return [32]byte{}, nil, nil, err
		}
		cc, err := r.rt.circuitTo(ctx, ip.relay, nil)
		if err != nil {
			continue
		}
		rep, err := cc.request(ctx, circuit.RCmdIntroduce1, m.Encode(), circuit.RCmdIntroduceAck)
		cc.close()
		if err != nil {
			continue
		}
		ack, err := rendez.DecodeIntroduceAck(rep.Data)
		if err != nil || ack.Status != rendez.AckOK {
			continue
		}
		return x, ip, m, nil
	}
	return [32]byte{}, nil, nil, ErrIntroRefused
}

func (r *remote) connect(ctx context.Context) error {
	intros, err := r.fetchDescriptor(ctx)
	if err != nil {
		return err
	}
	r.intros = intros
	avoid := map[link.NodeID]bool{}
	for _, ip := range intros {
		avoid[ip.relay.Peer] = true
	}
	rp, rendCC, cookie, r2ch, err := r.rendezvous(ctx, avoid)
	if err != nil {
		return err
	}
	id, err := session.NewID()
	if err != nil {
		rendCC.close()
		return err
	}
	pt := &rendez.IntroPlaintext{Cookie: cookie, RPRoutingID: rp.Static.ID(), RPOnionKey: rp.Static.B, SessionID: id}
	x, ip, m, err := r.introduce(ctx, pt)
	if err != nil {
		rendCC.close()
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 2*params.TunnelBuildTimeout)
	defer cancel()
	rep, err := rendCC.await(wctx, r2ch)
	if err != nil {
		rendCC.close()
		return fmt.Errorf("axon/runtime: the service did not come to the rendezvous: %w", err)
	}
	r2, err := rendez.DecodeRendezvous2(rep.Data)
	if err != nil {
		rendCC.close()
		return err
	}
	seed, err := rendez.ClientRendezvous(x, ip.encKey, r.kSvc(), m.X, r2.HS)
	if err != nil {
		rendCC.close()
		return err
	}
	cfg := r.rt.cfg.Session
	cfg.OnOrphan = func(s *session.Session, why error) { r.recover(s) }
	sess := session.NewClientWithID(seed, id, cfg)
	r.mu.Lock()
	r.sess, r.rp, r.rendCC = sess, rp, rendCC
	r.mu.Unlock()
	rendCC.attach(sess)
	r.registerResume(rendCC)
	return nil
}

// registerResume hands the RP the commitment a later case-A resume opens.
func (r *remote) registerResume(cc *clientCircuit) {
	n, commit, err := r.sess.NextResumeCommit()
	if err != nil {
		return
	}
	cc.send(circuit.RCmdResumeRegister, (&rendez.ResumeRegister{Commit: commit, Counter: n}).Encode())
}

// recover rebuilds a session's carrier after its circuit died.
func (r *remote) recover(s *session.Session) {
	r.mu.Lock()
	if r.closing || r.sess != s {
		r.mu.Unlock()
		return
	}
	rp := r.rp
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.rt.ctx, params.SessionOrphanRetention)
	defer cancel()
	for s.State() == session.Orphaned {
		if r.resumeA(ctx, s, rp) == nil || r.resumeB(ctx, s) == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (r *remote) resumeA(ctx context.Context, s *session.Session, rp *RelayInfo) error {
	cc, err := r.rt.circuitTo(ctx, rp, nil)
	if err != nil {
		return err
	}
	ctr, pre, err := s.ResumeRendezvous()
	if err != nil {
		cc.close()
		return err
	}
	rep, err := cc.request(ctx, circuit.RCmdResumeRendezvous, (&rendez.ResumeRendezvous{Preimage: pre, Counter: ctr}).Encode(),
		circuit.RCmdResumeStatus)
	if err != nil {
		cc.close()
		return err
	}
	st, err := rendez.DecodeResumeStatus(rep.Data)
	if err != nil || st.Status != rendez.ResumeOK {
		cc.close()
		return errors.New("axon/runtime: rendezvous point refused the resume")
	}
	r.mu.Lock()
	r.rendCC = cc
	r.mu.Unlock()
	cc.attach(s)
	r.registerResume(cc)
	return nil
}

func (r *remote) resumeB(ctx context.Context, s *session.Session) error {
	if intros, err := r.fetchDescriptor(ctx); err == nil {
		r.intros = intros
	}
	avoid := map[link.NodeID]bool{}
	for _, ip := range r.intros {
		avoid[ip.relay.Peer] = true
	}
	rp, cc, cookie, r2ch, err := r.rendezvous(ctx, avoid)
	if err != nil {
		return err
	}
	id, ctr, proof, err := s.ResumeIntro(cookie, rp.Static.ID())
	if err != nil {
		cc.close()
		return err
	}
	pt := &rendez.IntroPlaintext{Cookie: cookie, RPRoutingID: rp.Static.ID(), RPOnionKey: rp.Static.B,
		ResumePresent: true, SessionID: id, SessionCtr: ctr, SessionProof: proof}
	x, ip, m, err := r.introduce(ctx, pt)
	if err != nil {
		cc.close()
		return err
	}
	rep, err := cc.await(ctx, r2ch)
	if err != nil {
		cc.close()
		return err
	}
	r2, err := rendez.DecodeRendezvous2(rep.Data)
	if err != nil {
		cc.close()
		return err
	}
	seed, err := rendez.ClientRendezvous(x, ip.encKey, r.kSvc(), m.X, r2.HS)
	if err != nil {
		cc.close()
		return err
	}
	if err := s.Ratchet(seed); err != nil {
		cc.close()
		return err
	}
	r.mu.Lock()
	r.rp, r.rendCC = rp, cc
	r.mu.Unlock()
	cc.attach(s)
	r.registerResume(cc)
	return nil
}
