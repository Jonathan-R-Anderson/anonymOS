package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/rendez"
	"github.com/syndichan/maniwani/storage-client/internal/axon/session"
)

// The relay: what a node does for circuits that pass through it or end at it.
//
// Per circuit, one goroutine reads the cells coming from the client side. A
// cell for a circuit that continues is peeled one layer and written on; a cell
// for a circuit that ends here is opened and acted on -- EXTEND, the
// introduction and rendezvous commands, SESSION cells (forwarded across a
// rendezvous splice, or into this relay's own control session), and the resume
// commands. A second goroutine carries the next hop's backward cells toward the
// client, adding this hop's layer.
//
// Backward cells are sealed and written under one lock per circuit: the layer's
// counter is its nonce, so two cells sealed in one order and written in the
// other would arrive undecryptable.

type relay struct {
	rt     *Runtime
	table  *circuit.CircuitTable
	intro  *rendez.IntroPoint
	rp     *rendez.RendezvousPoint
	hsdir  *hsdirStore
	mu     sync.Mutex
	byRef  map[rendez.CircuitRef]*relayCirc
	refSeq uint64
}

type relayCirc struct {
	r       *relay
	ref     rendez.CircuitRef
	prev    link.CellStream
	rc      *circuit.RelayCircuit
	keys    circuit.KeySet
	bmu     sync.Mutex // backward seal + write
	mu      sync.Mutex
	next    link.CellStream
	ctl     *session.Session
	authKey *[32]byte
	dead    bool
}

func newRelay(rt *Runtime) *relay {
	r := &relay{
		rt:    rt,
		table: circuit.NewCircuitTable(time.Now),
		intro: rendez.NewIntroPoint(),
		rp:    rendez.NewRendezvousPoint(),
		hsdir: newHSDirStore(),
		byRef: map[rendez.CircuitRef]*relayCirc{},
	}
	r.intro.Limit = rendez.NewRateLimiter(50, 100, nil)
	go r.housekeeping()
	return r
}

func (r *relay) housekeeping() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.rt.ctx.Done():
			return
		case <-t.C:
			for _, ref := range r.rp.Expire() {
				r.destroyRef(ref)
			}
			r.table.PruneQuarantine()
			r.hsdir.prune()
		}
	}
}

func (r *relay) acceptLinks() {
	for {
		lk, err := r.rt.links.Accept(r.rt.ctx)
		if err != nil {
			return
		}
		go func() {
			for {
				cs, err := lk.AcceptCircuitStream(r.rt.ctx)
				if err != nil {
					return
				}
				go r.serveCircuit(lk, cs)
			}
		}()
	}
}

// answerCreate runs the ntor responder, trying this epoch's key and then the
// last one (a client may hold a directory from before the rotation).
func (r *relay) answerCreate(in *link.Cell) (circuit.KeySet, []byte, error) {
	htype, body, err := circuit.DecodeCreate(in.Payload)
	if err != nil {
		return circuit.KeySet{}, nil, err
	}
	if htype != circuit.HTypeNtorV1 {
		return circuit.KeySet{}, nil, circuit.ErrHandshakeType
	}
	for _, rg := range []struct {
		static circuit.RelayStatic
		b      [32]byte
	}{
		{r.rt.static(r.rt.routing), r.rt.routing.StaticPrivate()},
		{r.rt.static(r.rt.prevRtg), r.rt.prevRtg.StaticPrivate()},
	} {
		ks, reply, err := circuit.ServerHandshake(rand.Reader, rg.static, rg.b, body)
		if errors.Is(err, circuit.ErrWrongKey) {
			continue
		}
		return ks, reply, err
	}
	return circuit.KeySet{}, nil, circuit.ErrWrongKey
}

func (r *relay) serveCircuit(lk link.Link, cs link.CellStream) {
	first, err := cs.ReadCell()
	if err != nil {
		cs.Close()
		return
	}
	if first.Command != link.CmdCreate {
		cs.WriteCell(circuit.DestroyCell(cs.CircuitID(), circuit.ReasonProtocol))
		cs.Close()
		return
	}
	ks, reply, err := r.answerCreate(first)
	if err != nil {
		reason := circuit.ReasonProtocol
		if errors.Is(err, circuit.ErrWrongKey) {
			reason = circuit.ReasonWrongKey
		}
		cs.WriteCell(circuit.DestroyCell(cs.CircuitID(), reason))
		cs.Close()
		return
	}
	hw, err := circuit.NewHopWide(ks)
	if err != nil {
		cs.Close()
		return
	}
	rc, err := r.table.Admit(lk.RemoteID().String(), cs.CircuitID(), hw)
	if err != nil {
		cs.WriteCell(circuit.DestroyCell(cs.CircuitID(), circuit.ReasonResource))
		cs.Close()
		return
	}
	if err := cs.WriteCell(&link.Cell{Circuit: cs.CircuitID(), Command: link.CmdCreated,
		Payload: circuit.EncodeCreated(reply)}); err != nil {
		cs.Close()
		return
	}
	r.mu.Lock()
	r.refSeq++
	c := &relayCirc{r: r, ref: rendez.CircuitRef(r.refSeq), prev: cs, rc: rc, keys: ks}
	r.byRef[c.ref] = c
	r.mu.Unlock()
	defer c.teardown()

	for {
		cell, err := cs.ReadCell()
		if err != nil {
			return
		}
		switch cell.Command {
		case link.CmdPadding:
			continue
		case link.CmdDestroy:
			return
		case link.CmdRelay, link.CmdRelayBuild:
		default:
			return
		}
		c.mu.Lock()
		next := c.next
		c.mu.Unlock()
		if next != nil {
			res, err := circuit.ProcessForward(rc, cell, ks.Af, false)
			if err != nil {
				return
			}
			if err := next.WriteCell(res.Out); err != nil {
				return
			}
			continue
		}
		res, err := circuit.ProcessForward(rc, cell, ks.Af, true)
		if err != nil {
			return
		}
		if err := r.terminal(c, res.Relay); err != nil {
			return
		}
	}
}

// sendBackward originates a relay message toward this circuit's client.
func (c *relayCirc) sendBackward(msg *circuit.RelayCell) error {
	c.bmu.Lock()
	defer c.bmu.Unlock()
	if c.dead {
		return ErrClosed
	}
	cell, err := circuit.SendBackward(c.rc, c.keys.Af, msg)
	if err != nil {
		return err
	}
	return c.prev.WriteCell(cell)
}

// backwardPump carries the next hop's cells toward the client.
func (c *relayCirc) backwardPump(next link.CellStream) {
	defer c.prev.Close()
	for {
		cell, err := next.ReadCell()
		if err != nil {
			return
		}
		switch cell.Command {
		case link.CmdRelay, link.CmdRelayBuild:
			c.bmu.Lock()
			out, err := circuit.WrapBackwardHop(c.rc, cell)
			if err == nil {
				err = c.prev.WriteCell(out)
			}
			c.bmu.Unlock()
			if err != nil {
				return
			}
		case link.CmdDestroy:
			c.prev.WriteCell(circuit.DestroyCell(c.rc.PrevID, circuit.ReasonFinished))
			return
		}
	}
}

func (r *relay) lookup(ref rendez.CircuitRef) *relayCirc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byRef[ref]
}

func (r *relay) destroyRef(ref rendez.CircuitRef) {
	c := r.lookup(ref)
	if c == nil {
		return
	}
	c.bmu.Lock()
	c.prev.WriteCell(circuit.DestroyCell(c.rc.PrevID, circuit.ReasonFinished))
	c.bmu.Unlock()
	c.prev.Close()
}

func (c *relayCirc) teardown() {
	r := c.r
	c.bmu.Lock()
	if c.dead {
		c.bmu.Unlock()
		return
	}
	c.dead = true
	c.bmu.Unlock()
	r.mu.Lock()
	delete(r.byRef, c.ref)
	r.mu.Unlock()
	if c.authKey != nil {
		r.intro.Teardown(*c.authKey)
	}
	// A spliced pair: the client side dropping holds the service side for a
	// case-A resume when a commitment is registered; otherwise, and when the
	// service side drops, the other side goes too.
	if svc, keep := r.rp.ClientLost(c.ref); svc != 0 && !keep {
		r.destroyRef(svc)
	}
	if cl, ok := r.rp.ServiceLost(c.ref); ok {
		r.destroyRef(cl)
	}
	c.mu.Lock()
	next, ctl := c.next, c.ctl
	c.mu.Unlock()
	if next != nil {
		next.WriteCell(circuit.DestroyCell(c.rc.NextID, circuit.ReasonFinished))
		next.Close()
	}
	if ctl != nil {
		ctl.Close()
	}
	c.prev.Close()
	r.table.Teardown(c.rc)
}

// terminal acts on a relay message for a circuit that ends here.
func (r *relay) terminal(c *relayCirc, msg *circuit.RelayCell) error {
	switch msg.Cmd {
	case circuit.RCmdExtend:
		return r.extend(c, msg)
	case circuit.RCmdDrop:
		return nil
	case circuit.RCmdEstablishIntro:
		e, err := rendez.DecodeEstablishIntro(msg.Data)
		if err != nil {
			return err
		}
		if !ed25519.Verify(ed25519.PublicKey(e.AuthKey[:]), establishIntroMessage(e.AuthKey, c.keys.Af), e.Sig) {
			return errors.New("axon/runtime: ESTABLISH_INTRO signature")
		}
		r.intro.Establish(e.AuthKey, c.ref)
		ak := e.AuthKey
		c.authKey = &ak
		return c.sendBackward(rendez.RelayCell(circuit.RCmdIntroEstablished,
			(&rendez.IntroEstablished{Status: rendez.AckOK}).Encode()))
	case circuit.RCmdIntroduce1:
		m, err := rendez.DecodeIntroduce1(msg.Data)
		if err != nil {
			return err
		}
		svcRef, status, _ := r.intro.Admit(m)
		if status == rendez.AckOK {
			if svc := r.lookup(svcRef); svc != nil {
				svc.sendBackward(rendez.RelayCell(circuit.RCmdIntroduce2, encodeIntroduce2(m, status)))
			} else {
				status = rendez.AckUnknownAuthKey
			}
		}
		return c.sendBackward(rendez.RelayCell(circuit.RCmdIntroduceAck,
			(&rendez.IntroduceAck{Status: status}).Encode()))
	case circuit.RCmdEstablishRendezvous:
		e, err := rendez.DecodeEstablishRendezvous(msg.Data)
		if err != nil {
			return err
		}
		status := byte(0)
		if err := r.rp.Establish(e.Cookie, c.ref); err != nil {
			status = 1
		}
		return c.sendBackward(rendez.RelayCell(circuit.RCmdRendezvousEstablished, []byte{status}))
	case circuit.RCmdRendezvous1:
		r1, err := rendez.DecodeRendezvous1(msg.Data)
		if err != nil {
			return err
		}
		clientRef, err := r.rp.Splice(r1.Cookie, c.ref)
		if err != nil {
			return err
		}
		cl := r.lookup(clientRef)
		if cl == nil {
			return errors.New("axon/runtime: rendezvous client circuit gone")
		}
		return cl.sendBackward(rendez.RelayCell(circuit.RCmdRendezvous2, (&rendez.Rendezvous2{HS: r1.HS}).Encode()))
	case circuit.RCmdSession:
		if peerRef, ok := r.rp.Peer(c.ref); ok {
			if p := r.lookup(peerRef); p != nil {
				p.sendBackward(rendez.RelayCell(circuit.RCmdSession, msg.Data))
			}
			return nil
		}
		return c.controlReceive(msg.Data)
	case circuit.RCmdResumeRegister:
		rr, err := rendez.DecodeResumeRegister(msg.Data)
		if err != nil {
			return err
		}
		r.rp.RegisterResume(c.ref, rr.Counter, rr.Commit)
		return nil
	case circuit.RCmdResumeRendezvous:
		rr, err := rendez.DecodeResumeRendezvous(msg.Data)
		if err != nil {
			return err
		}
		st := rendez.ResumeOK
		if _, err := r.rp.Resume(c.ref, rr.Counter, rr.Preimage); err != nil {
			st = rendez.ResumeRefused
		}
		return c.sendBackward(rendez.RelayCell(circuit.RCmdResumeStatus, (&rendez.ResumeStatus{Status: st}).Encode()))
	}
	return nil // unknown terminal commands are dropped, not fatal
}

// extend telescopes the circuit to the relay the client named.
func (r *relay) extend(c *relayCirc, msg *circuit.RelayCell) error {
	c.mu.Lock()
	already := c.next != nil
	c.mu.Unlock()
	if already {
		return errors.New("axon/runtime: EXTEND on a circuit that already continues")
	}
	self := r.rt.static(r.rt.routing).ID()
	tgt, err := circuit.ParseExtend(c.rc, self, msg)
	if err != nil {
		return err
	}
	ls, err := decodeLinkSpec(tgt.LinkSpecs)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.rt.ctx, params.ExtendTimeout)
	defer cancel()
	lk, err := r.rt.linkTo(ctx, ls)
	if err != nil {
		return c.sendBackward(&circuit.RelayCell{Cmd: circuit.RCmdTruncated, Data: []byte{byte(circuit.ReasonTimeout)}})
	}
	ncs, err := lk.OpenCircuitStream(ctx, c.rc.NextID)
	if err != nil {
		r.rt.dropLink(ls.Peer)
		return c.sendBackward(&circuit.RelayCell{Cmd: circuit.RCmdTruncated, Data: []byte{byte(circuit.ReasonTimeout)}})
	}
	if err := ncs.WriteCell(&link.Cell{Circuit: c.rc.NextID, Command: link.CmdCreate,
		Payload: circuit.EncodeCreate(tgt.HType, tgt.Handshake)}); err != nil {
		ncs.Close()
		return err
	}
	type res struct {
		cell *link.Cell
		err  error
	}
	ch := make(chan res, 1)
	go func() { cell, err := ncs.ReadCell(); ch <- res{cell, err} }()
	var in *link.Cell
	select {
	case got := <-ch:
		if got.err != nil {
			ncs.Close()
			return got.err
		}
		in = got.cell
	case <-ctx.Done():
		ncs.Close()
		return ctx.Err()
	}
	if in.Command != link.CmdCreated {
		ncs.Close()
		return c.sendBackward(&circuit.RelayCell{Cmd: circuit.RCmdTruncated, Data: []byte{byte(circuit.ReasonProtocol)}})
	}
	reply, err := circuit.DecodeCreated(in.Payload)
	if err != nil {
		ncs.Close()
		return err
	}
	c.mu.Lock()
	c.next = ncs
	c.mu.Unlock()
	r.table.Link(c.rc, ls.Peer.String())
	go c.backwardPump(ncs)
	return c.sendBackward(&circuit.RelayCell{Cmd: circuit.RCmdExtended, Data: circuit.EncodeExtended(reply)})
}

// establishIntroMessage is what an intro point's auth key signs: bound to the
// circuit's own key, so the signature cannot be replayed onto another circuit.
func establishIntroMessage(authKey [32]byte, af [32]byte) []byte {
	m := make([]byte, 0, 24+64)
	m = append(m, "axon:establish-intro:v1"...)
	m = append(m, authKey[:]...)
	return append(m, af[:]...)
}

// encodeIntroduce2 is INTRODUCE2: the INTRODUCE1 body verbatim, then the intro
// point's admission verdict.
func encodeIntroduce2(m *rendez.Introduce1, verdict rendez.AckStatus) []byte {
	return append(m.Encode(), byte(verdict))
}

func decodeIntroduce2(b []byte) (*rendez.Introduce1, rendez.AckStatus, error) {
	if len(b) < 2 {
		return nil, 0, rendez.ErrMalformed
	}
	m, err := rendez.DecodeIntroduce1(b[:len(b)-1])
	return m, rendez.AckStatus(b[len(b)-1]), err
}
