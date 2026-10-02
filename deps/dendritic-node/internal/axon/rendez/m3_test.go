package rendez

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/circuit"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
)

// M3: a session over real rendezvous circuits survives their death.
//
// Every leg is a real 3-hop circuit (ntor handshakes, wide-block onion layers,
// the end-to-end authenticator); the third hop of each leg is the rendezvous
// point, which forwards SESSION cells between the two legs it has spliced and
// can read nothing inside them. Case A (the client's circuit dies, the RP
// lives) and case B (the RP dies) are both run, mid-transfer, through the RP's
// actual resume state and the actual wire bodies.

// legE is newLeg without testing.T, for use off the test goroutine.
func legE() (*leg, error) {
	l := &leg{}
	if _, err := rand.Read(l.af[:]); err != nil {
		return nil, err
	}
	for i := 0; i < 3; i++ {
		var rid, bPriv [32]byte
		rand.Read(rid[:])
		rand.Read(bPriv[:])
		bPub, err := curve25519.X25519(bPriv[:], curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		var static circuit.RelayStatic
		static.RID = rid
		copy(static.B[:], bPub)
		h, create, err := circuit.NewClientHandshake(rand.Reader, static)
		if err != nil {
			return nil, err
		}
		rk, reply, err := circuit.ServerHandshake(rand.Reader, static, bPriv, create)
		if err != nil {
			return nil, err
		}
		ck, err := h.Complete(reply)
		if err != nil {
			return nil, err
		}
		c, err := circuit.NewHopWide(ck)
		if err != nil {
			return nil, err
		}
		r, err := circuit.NewHopWide(rk)
		if err != nil {
			return nil, err
		}
		l.clients = append(l.clients, c)
		l.relays = append(l.relays, r)
	}
	return l, nil
}

// fwd carries a relay cell from the leg's endpoint to the RP (its last hop).
func fwd(l *leg, msg *circuit.RelayCell) (*circuit.RelayCell, error) {
	inner, err := msg.Encode()
	if err != nil {
		return nil, err
	}
	block, err := circuit.SealInnermost(l.af, inner)
	if err != nil {
		return nil, err
	}
	if err := circuit.WideSealForward(l.clients, block); err != nil {
		return nil, err
	}
	for _, r := range l.relays {
		if err := circuit.WideOpenForwardAtHop(r, block); err != nil {
			return nil, err
		}
	}
	got, err := circuit.OpenInnermost(l.af, block)
	if err != nil {
		return nil, err
	}
	return circuit.DecodeRelay(got)
}

// bwd carries a relay cell from the RP back down the leg to its endpoint.
func bwd(l *leg, msg *circuit.RelayCell) (*circuit.RelayCell, error) {
	inner, err := msg.Encode()
	if err != nil {
		return nil, err
	}
	block, err := circuit.SealInnermost(l.af, inner)
	if err != nil {
		return nil, err
	}
	for i := len(l.relays) - 1; i >= 0; i-- {
		if err := circuit.WideSealBackwardAtHop(l.relays[i], block); err != nil {
			return nil, err
		}
	}
	if err := circuit.WideOpenBackwardAtClient(l.clients, block); err != nil {
		return nil, err
	}
	got, err := circuit.OpenInnermost(l.af, block)
	if err != nil {
		return nil, err
	}
	return circuit.DecodeRelay(got)
}

// rpNode is a rendezvous point and the circuits that end at it. One mutex
// serialises all the onion crypto at the node, because a hop's counters are
// per direction and must advance in cell order.
type rpNode struct {
	rp        *RendezvousPoint
	routingID [32]byte
	mu        sync.Mutex
	dead      bool
	ends      map[CircuitRef]*legCarrier
	nextRef   CircuitRef
	cells     atomic.Int64 // SESSION cells forwarded
}

func newRPNode() *rpNode {
	n := &rpNode{rp: NewRendezvousPoint(), ends: map[CircuitRef]*legCarrier{}, nextRef: 100}
	rand.Read(n.routingID[:])
	return n
}

// legCarrier is one endpoint's circuit to the RP, as a session.Carrier.
type legCarrier struct {
	node  *rpNode
	ref   CircuitRef
	l     *leg
	sess  *session.Session
	q     chan []byte
	dead  atomic.Bool
	first chan []byte // the first SESSION packet this carrier sends, for the eavesdropper
}

func (n *rpNode) open(sess *session.Session) (*legCarrier, error) {
	l, err := legE()
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.nextRef++
	c := &legCarrier{node: n, ref: n.nextRef, l: l, sess: sess, q: make(chan []byte, 8192),
		first: make(chan []byte, 1)}
	n.ends[c.ref] = c
	n.mu.Unlock()
	go c.pump()
	return c, nil
}

func (c *legCarrier) Send(p []byte) error {
	if c.dead.Load() {
		return errors.New("circuit destroyed")
	}
	select {
	case c.first <- append([]byte(nil), p...):
	default:
	}
	c.q <- append([]byte(nil), p...)
	return nil
}

// pump forwards this endpoint's SESSION cells: up its own leg to the RP, across
// the splice, down the peer's leg.
func (c *legCarrier) pump() {
	for p := range c.q {
		n := c.node
		n.mu.Lock()
		if n.dead || c.dead.Load() {
			n.mu.Unlock()
			continue
		}
		atRP, err := fwd(c.l, RelayCell(circuit.RCmdSession, p))
		if err != nil || atRP.Cmd != circuit.RCmdSession {
			n.mu.Unlock()
			continue
		}
		peerRef, ok := n.rp.Peer(c.ref)
		peer := n.ends[peerRef]
		if !ok || peer == nil || peer.dead.Load() {
			n.mu.Unlock() // the other side is gone or held: the cell is lost
			continue
		}
		out, err := bwd(peer.l, atRP)
		n.mu.Unlock()
		if err != nil {
			continue
		}
		n.cells.Add(1)
		_ = peer.sess.Receive(peer, out.Data)
	}
}

// control sends one control relay cell from an endpoint to the RP and runs the
// RP's handler on it, returning the RP's reply down the same leg.
func (n *rpNode) control(c *legCarrier, cmd circuit.RCmd, body []byte,
	handle func(*circuit.RelayCell) *circuit.RelayCell) (*circuit.RelayCell, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dead {
		return nil, errors.New("rendezvous point is down")
	}
	atRP, err := fwd(c.l, RelayCell(cmd, body))
	if err != nil {
		return nil, err
	}
	reply := handle(atRP)
	if reply == nil {
		return nil, nil
	}
	return bwd(c.l, reply)
}

func (n *rpNode) kill() {
	n.mu.Lock()
	n.dead = true
	ends := make([]*legCarrier, 0, len(n.ends))
	for _, e := range n.ends {
		ends = append(ends, e)
	}
	n.mu.Unlock()
	for _, e := range ends {
		e.dead.Store(true)
		e.sess.CarrierLost(e, errors.New("rendezvous point died"))
	}
}

// killClientLeg destroys one client circuit; the RP holds the service side.
func (n *rpNode) killClientLeg(c *legCarrier) (held bool) {
	c.dead.Store(true)
	n.mu.Lock()
	_, held = n.rp.ClientLost(c.ref)
	n.mu.Unlock()
	c.sess.CarrierLost(c, errors.New("client circuit destroyed"))
	return held
}

// world is the client, the service and the rendezvous machinery around them.
type world struct {
	t       *testing.T
	svcKeys *service
	cli     *session.Session
	svc     *session.Session

	mu        sync.Mutex
	node      *rpNode
	cliC      *legCarrier
	svcC      *legCarrier
	caseA     atomic.Int64
	caseB     atomic.Int64
	resumeErr error
	seed0     [32]byte // the first KEY_SEED: what an adversary who compromised the session holds
	cfg       session.Config
}

// splice runs ESTABLISH_RENDEZVOUS / RENDEZVOUS1 on fresh legs to node and
// registers the client's first resume commitment.
func (w *world) splice(node *rpNode, cookie Cookie) (cc, sc *legCarrier, err error) {
	if cc, err = node.open(w.cli); err != nil {
		return
	}
	if sc, err = node.open(w.svc); err != nil {
		return
	}
	er := &EstablishRendezvous{Cookie: cookie}
	if _, err = node.control(cc, circuit.RCmdEstablishRendezvous, er.Encode(), func(m *circuit.RelayCell) *circuit.RelayCell {
		got, e := DecodeEstablishRendezvous(m.Data)
		if e == nil {
			e = node.rp.Establish(got.Cookie, cc.ref)
		}
		if e != nil {
			err = e
		}
		return nil
	}); err != nil {
		return
	}
	r1 := &Rendezvous1{Cookie: cookie}
	if _, err = node.control(sc, circuit.RCmdRendezvous1, r1.Encode(), func(m *circuit.RelayCell) *circuit.RelayCell {
		got, e := DecodeRendezvous1(m.Data)
		if e == nil {
			_, e = node.rp.Splice(got.Cookie, sc.ref)
		}
		if e != nil {
			err = e
		}
		return nil
	}); err != nil {
		return
	}
	err = w.register(node, cc)
	return
}

// register sends RESUME_REGISTER with the client's next commitment.
func (w *world) register(node *rpNode, cc *legCarrier) error {
	n, commit, err := w.cli.NextResumeCommit()
	if err != nil {
		return err
	}
	var regErr error
	_, err = node.control(cc, circuit.RCmdResumeRegister, (&ResumeRegister{Commit: commit, Counter: n}).Encode(),
		func(m *circuit.RelayCell) *circuit.RelayCell {
			rr, e := DecodeResumeRegister(m.Data)
			if e == nil {
				e = node.rp.RegisterResume(cc.ref, rr.Counter, rr.Commit)
			}
			regErr = e
			return nil
		})
	if err != nil {
		return err
	}
	return regErr
}

// resumeA tries case A: a fresh circuit to the same RP, RESUME_RENDEZVOUS.
func (w *world) resumeA(node *rpNode) (*legCarrier, error) {
	cc, err := node.open(w.cli)
	if err != nil {
		return nil, err
	}
	ctr, pre, err := w.cli.ResumeRendezvous()
	if err != nil {
		return nil, err
	}
	reply, err := node.control(cc, circuit.RCmdResumeRendezvous,
		(&ResumeRendezvous{Preimage: pre, Counter: ctr}).Encode(),
		func(m *circuit.RelayCell) *circuit.RelayCell {
			st := ResumeRefused
			if rr, e := DecodeResumeRendezvous(m.Data); e == nil {
				if _, e := node.rp.Resume(cc.ref, rr.Counter, rr.Preimage); e == nil {
					st = ResumeOK
				}
			}
			return RelayCell(circuit.RCmdResumeStatus, (&ResumeStatus{Status: st}).Encode())
		})
	if err != nil {
		return nil, err
	}
	st, err := DecodeResumeStatus(reply.Data)
	if err != nil {
		return nil, err
	}
	if st.Status != ResumeOK {
		return nil, errors.New("RP refused the resume")
	}
	if err := w.register(node, cc); err != nil {
		return nil, err
	}
	return cc, nil
}

// resumeB is case B: a new RP, a new introduction carrying session_resume, a
// fresh rendezvous handshake, and a ratchet on both ends.
func (w *world) resumeB() (*rpNode, *legCarrier, *legCarrier, error) {
	node := newRPNode()
	cookie, err := NewCookie(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	id, ctr, proof, err := w.cli.ResumeIntro(cookie, node.routingID)
	if err != nil {
		return nil, nil, nil, err
	}
	var rk [32]byte
	rand.Read(rk[:])
	pt := &IntroPlaintext{Cookie: cookie, RPRoutingID: node.routingID, RPOnionKey: rk,
		ResumePresent: true, SessionID: id, SessionCtr: ctr, SessionProof: proof}
	sk := w.svcKeys
	intro, x, err := SealIntro(rand.Reader, sk.bEnc, sk.kSvc, sk.authKey, sk.subcred, pt, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	// --- the service ---
	in, err := OpenIntro(sk.bEncPriv, sk.bEnc, sk.kSvc, sk.subcred, intro)
	if err != nil {
		return nil, nil, nil, err
	}
	if !in.ResumePresent || session.ID(in.SessionID) != w.svc.ID() {
		return nil, nil, nil, errors.New("introduction does not name the session")
	}
	if err := w.svc.AcceptResume(in.SessionCtr, in.SessionProof, in.Cookie, in.RPRoutingID); err != nil {
		return nil, nil, nil, err
	}
	seedS, hs, err := ServiceRendezvous(rand.Reader, sk.bEncPriv, sk.bEnc, sk.kSvc, intro.X)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := w.svc.Ratchet(seedS); err != nil {
		return nil, nil, nil, err
	}
	// --- the client completes; both legs splice at the new RP ---
	seedC, err := ClientRendezvous(x, sk.bEnc, sk.kSvc, intro.X, hs)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := w.cli.Ratchet(seedC); err != nil {
		return nil, nil, nil, err
	}
	cc, sc, err := w.splice(node, cookie)
	if err != nil {
		return nil, nil, nil, err
	}
	return node, cc, sc, nil
}

func (w *world) onOrphan(s *session.Session, why error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s.State() != session.Orphaned {
		return
	}
	if cc, err := w.resumeA(w.node); err == nil {
		w.caseA.Add(1)
		w.cliC = cc
		w.cli.Attach(cc)
		return
	}
	node, cc, sc, err := w.resumeB()
	if err != nil {
		w.resumeErr = fmt.Errorf("case B: %w", err)
		return
	}
	w.caseB.Add(1)
	w.node, w.cliC, w.svcC = node, cc, sc
	w.svc.Attach(sc)
	w.cli.Attach(cc)
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, svcKeys: newService(t)}
	cs, ss, _ := fullRendezvous(t, w.svcKeys)
	w.seed0 = cs
	cfg := session.DefaultConfig()
	cfg.MinRTO, cfg.MaxRTO, cfg.ProbeTimeout = 100*time.Millisecond, time.Second, 2*time.Second
	ccfg := cfg
	ccfg.OnOrphan = w.onOrphan
	var err error
	if w.cli, err = session.NewClient(cs, ccfg); err != nil {
		t.Fatal(err)
	}
	w.svc = session.NewService(ss, w.cli.ID(), cfg)
	w.cfg = cfg
	w.node = newRPNode()
	cookie, _ := NewCookie(rand.Reader)
	w.mu.Lock()
	w.cliC, w.svcC, err = w.splice(w.node, cookie)
	w.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	w.svc.Attach(w.svcC)
	w.cli.Attach(w.cliC)
	t.Cleanup(func() { w.cli.Close(); w.svc.Close() })
	return w
}

// TestM3SessionSurvivesCaseAAndCaseB runs a transfer in both directions over
// real rendezvous circuits through: the client's circuit dying (case A, same
// RP), the RP itself dying (case B, new RP, ratchet), and the client's circuit
// at the new RP dying (case A again, under the ratcheted keys).
func TestM3SessionSurvivesCaseAAndCaseB(t *testing.T) {
	w := newWorld(t)
	const size = 2 << 20
	up, down := make([]byte, size), make([]byte, size)
	rand.Read(up)
	rand.Read(down)

	cs, err := w.cli.OpenStream([]byte("m3"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ss, err := w.svc.AcceptStream(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	var nUp, nDown atomic.Int64
	var gotUp, gotDown []byte
	var e1, e2, e3, e4 error
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); _, e1 = cs.Write(up); cs.CloseWrite() }()
	go func() { defer wg.Done(); _, e2 = ss.Write(down); ss.CloseWrite() }()
	go func() { defer wg.Done(); gotUp, e3 = io.ReadAll(countR{ss, &nUp}) }()
	go func() { defer wg.Done(); gotDown, e4 = io.ReadAll(countR{cs, &nDown}) }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	waitFor := func(frac int64) {
		for nUp.Load() < size*frac/10 || nDown.Load() < size*frac/10 {
			select {
			case <-done:
				t.Fatalf("transfer finished before the %d0%% event", frac)
			case <-time.After(time.Millisecond):
			}
		}
	}

	// 1. case A: the client's circuit dies; the RP holds the service's.
	waitFor(3)
	w.mu.Lock()
	node, c1 := w.node, w.cliC
	w.mu.Unlock()
	if !node.killClientLeg(c1) {
		t.Fatal("the RP did not hold the service circuit for a registered commitment")
	}
	waitEq(t, &w.caseA, 1)
	if node.rp.Held() != 0 {
		t.Fatalf("RP still holds %d circuits after the resume", node.rp.Held())
	}

	// 2. case B: the RP dies.
	waitFor(5)
	before := w.cli.Stats().Ratchets
	node.kill()
	waitEq(t, &w.caseB, 1)
	if w.cli.Stats().Ratchets != before+1 || w.svc.Stats().Ratchets != 1 {
		t.Fatalf("ratchets: client %d service %d", w.cli.Stats().Ratchets, w.svc.Stats().Ratchets)
	}

	// 3. case A again, at the new RP, under the ratcheted root.
	waitFor(8)
	w.mu.Lock()
	node2, c2 := w.node, w.cliC
	w.mu.Unlock()
	if node2 == node {
		t.Fatal("case B did not move to a new RP")
	}
	if !node2.killClientLeg(c2) {
		t.Fatal("new RP did not hold the service circuit")
	}
	waitEq(t, &w.caseA, 2)

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		w.mu.Lock()
		re := w.resumeErr
		w.mu.Unlock()
		t.Fatalf("transfer did not finish (up %d down %d, resume error %v)", nUp.Load(), nDown.Load(), re)
	}
	for _, e := range []error{e1, e2, e3, e4} {
		if e != nil {
			t.Fatalf("application-visible error: %v", e)
		}
	}
	if sha256.Sum256(gotUp) != sha256.Sum256(up) || sha256.Sum256(gotDown) != sha256.Sum256(down) {
		t.Fatalf("bytes lost or duplicated: up %d/%d down %d/%d", len(gotUp), size, len(gotDown), size)
	}
	cst, sst := w.cli.Stats(), w.svc.Stats()
	t.Logf("M3: %d MiB each way over real 3+3-hop rendezvous circuits; case A x%d, case B x%d; "+
		"client %+v; service %+v; SESSION cells forwarded by the RPs: %d + %d",
		size>>20, w.caseA.Load(), w.caseB.Load(), cst, sst, node.cells.Load(), node2.cells.Load())
	if cst.Hostile != 0 || sst.Hostile != 0 {
		t.Fatalf("an honest RP produced hostile counts: %d / %d", cst.Hostile, sst.Hostile)
	}
}

type countR struct {
	r io.Reader
	n *atomic.Int64
}

func (c countR) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n.Add(int64(n))
	return n, err
}

func waitEq(t *testing.T, v *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for v.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("counter reached %d, want %d", v.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestCaseBRatchetLocksOutTheOldKeys is the post-compromise property §9.8
// claims for case B and only for case B: an adversary holding every key from
// before the ratchet reads nothing sealed after it.
func TestCaseBRatchetLocksOutTheOldKeys(t *testing.T) {
	w := newWorld(t)
	w.mu.Lock()
	c0 := w.cliC
	w.mu.Unlock()
	cs, _ := w.cli.OpenStream(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ss, err := w.svc.AcceptStream(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	cs.Write([]byte("before"))
	io.ReadFull(ss, make([]byte, 6))

	// The adversary: a service end built from the original KEY_SEED, i.e.
	// holding every session key from before case B.
	adv := session.NewService(w.seed0, w.cli.ID(), w.cfg)
	defer adv.Close()
	var before []byte
	select {
	case before = <-c0.first:
	default:
		t.Fatal("nothing captured on the first carrier")
	}
	if err := adv.Receive(nil, before); err != nil {
		t.Fatalf("the adversary cannot even read a pre-ratchet packet (%v): the test proves nothing", err)
	}

	w.mu.Lock()
	oldNode := w.node
	w.mu.Unlock()
	oldNode.kill()
	waitEq(t, &w.caseB, 1)
	w.mu.Lock()
	newC := w.cliC
	w.mu.Unlock()
	cs.Write([]byte("after"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(ss, got); err != nil || string(got) != "after" {
		t.Fatalf("after the ratchet: %q %v", got, err)
	}
	var after []byte
	select {
	case after = <-newC.first:
	default:
		t.Fatal("nothing captured on the new carrier")
	}
	if err := adv.Receive(nil, after); err == nil {
		t.Fatal("post-compromise security falsified: the pre-ratchet keys opened a post-ratchet packet")
	}
	if adv.Stats().PacketsReceived != 1 {
		t.Fatalf("adversary accepted %d packets, want only the pre-ratchet one", adv.Stats().PacketsReceived)
	}
}
