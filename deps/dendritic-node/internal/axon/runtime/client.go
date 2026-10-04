package runtime

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/circuit"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/link"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/params"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
)

// Client circuits: built hop by hop over a link to the guard, keeping each
// hop's KeySet (the library's Builder drops it, and the terminal hop's keys are
// what end-to-end messages and control sessions need). One goroutine reads the
// backward cells and routes them: SESSION cells to the session riding the
// circuit, INTRODUCE2 to the service that owns an intro circuit, and every other
// reply to whoever is waiting for that command.

var (
	ErrCircuitClosed = errors.New("axon/runtime: circuit closed")
	ErrTruncated     = errors.New("axon/runtime: a relay could not extend the circuit")
)

type hopKeys struct {
	ri *RelayInfo
	ks circuit.KeySet
}

type clientCircuit struct {
	rt   *Runtime
	c    *circuit.Circuit
	cs   link.CellStream
	hops []hopKeys

	wmu sync.Mutex // forward seal + write

	mu          sync.Mutex
	waiters     map[circuit.RCmd]chan *circuit.RelayCell
	onSession   func(data []byte)
	onIntroduce func(data []byte)
	onDeath     []func()

	done chan struct{}
	once sync.Once
}

func (cc *clientCircuit) terminal() *RelayInfo { return cc.hops[len(cc.hops)-1].ri }
func (cc *clientCircuit) termKeys() circuit.KeySet {
	return cc.hops[len(cc.hops)-1].ks
}

// readCell reads one cell with a deadline.
func readCellTimeout(cs link.CellStream, d time.Duration) (*link.Cell, error) {
	type res struct {
		c   *link.Cell
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := cs.ReadCell(); ch <- res{c, err} }()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-time.After(d):
		cs.Close()
		return nil, context.DeadlineExceeded
	}
}

// buildCircuit builds a circuit along path (path[0] is the guard).
func (rt *Runtime) buildCircuit(ctx context.Context, path []*RelayInfo) (*clientCircuit, error) {
	if len(path) == 0 || len(path) > params.MaxHops {
		return nil, fmt.Errorf("axon/runtime: path of %d hops", len(path))
	}
	lk, err := rt.linkTo(ctx, path[0])
	if err != nil {
		return nil, err
	}
	id, err := circuit.AllocateID()
	if err != nil {
		return nil, err
	}
	cs, err := lk.OpenCircuitStream(ctx, id)
	if err != nil {
		rt.dropLink(path[0].Peer)
		return nil, err
	}
	c, err := circuit.NewCircuit(id, circuit.ClassInteractive, time.Now())
	if err != nil {
		cs.Close()
		return nil, err
	}
	cc := &clientCircuit{rt: rt, c: c, cs: cs, waiters: map[circuit.RCmd]chan *circuit.RelayCell{},
		done: make(chan struct{})}

	// First hop: CREATE / CREATED.
	h, body, err := circuit.NewClientHandshake(rand.Reader, path[0].Static)
	if err != nil {
		cs.Close()
		return nil, err
	}
	if err := cs.WriteCell(&link.Cell{Circuit: id, Command: link.CmdCreate,
		Payload: circuit.EncodeCreate(circuit.HTypeNtorV1, body)}); err != nil {
		cs.Close()
		return nil, err
	}
	in, err := readCellTimeout(cs, params.CreateTimeout)
	if err != nil {
		return nil, err
	}
	if in.Command != link.CmdCreated {
		cs.Close()
		return nil, fmt.Errorf("axon/runtime: first hop answered %s", in.Command)
	}
	reply, err := circuit.DecodeCreated(in.Payload)
	if err != nil {
		cs.Close()
		return nil, err
	}
	ks, err := h.Complete(reply)
	if err != nil {
		cs.Close()
		return nil, err
	}
	if err := cc.addHop(path[0], ks); err != nil {
		cs.Close()
		return nil, err
	}

	// Further hops: EXTEND / EXTENDED, through the hops already built.
	for _, ri := range path[1:] {
		if err := cc.extend(ri); err != nil {
			cs.Close()
			return nil, err
		}
	}
	go cc.reader()
	return cc, nil
}

func (cc *clientCircuit) addHop(ri *RelayInfo, ks circuit.KeySet) error {
	hw, err := circuit.NewHopWide(ks)
	if err != nil {
		return err
	}
	if err := cc.c.AddHop(&circuit.Hop{Static: ri.Static, Crypto: hw}); err != nil {
		return err
	}
	cc.hops = append(cc.hops, hopKeys{ri: ri, ks: ks})
	return nil
}

func (cc *clientCircuit) extend(ri *RelayInfo) error {
	h, body, err := circuit.NewClientHandshake(rand.Reader, ri.Static)
	if err != nil {
		return err
	}
	msg := &circuit.RelayCell{Cmd: circuit.RCmdExtend,
		Data: circuit.EncodeExtend(ri.Static.ID(), encodeLinkSpec(ri), circuit.HTypeNtorV1, body)}
	af := cc.termKeys().Af
	block, err := cc.c.SendRelay(af, msg)
	if err != nil {
		return err
	}
	if err := cc.cs.WriteCell(&link.Cell{Circuit: cc.c.ID(), Command: link.CmdRelayBuild,
		Flags: link.FlagEarly, Payload: block}); err != nil {
		return err
	}
	in, err := readCellTimeout(cc.cs, params.ExtendTimeout)
	if err != nil {
		return err
	}
	if in.Command == link.CmdDestroy {
		return ErrTruncated
	}
	rep, err := cc.c.RecvRelay(af, in)
	if err != nil {
		return err
	}
	if rep.Cmd == circuit.RCmdTruncated {
		return ErrTruncated
	}
	if rep.Cmd != circuit.RCmdExtended {
		return fmt.Errorf("axon/runtime: expected EXTENDED, got %s", rep.Cmd)
	}
	hs, err := circuit.DecodeExtended(rep.Data)
	if err != nil {
		return err
	}
	ks, err := h.Complete(hs)
	if err != nil {
		return err
	}
	return cc.addHop(ri, ks)
}

func (cc *clientCircuit) reader() {
	defer cc.die()
	af := cc.termKeys().Af
	for {
		cell, err := cc.cs.ReadCell()
		if err != nil {
			return
		}
		switch cell.Command {
		case link.CmdDestroy:
			return
		case link.CmdRelay, link.CmdRelayBuild:
		default:
			continue
		}
		msg, err := cc.c.RecvRelay(af, cell)
		if err != nil {
			return // a cell that does not authenticate ends the circuit
		}
		cc.dispatch(msg)
	}
}

func (cc *clientCircuit) dispatch(msg *circuit.RelayCell) {
	cc.mu.Lock()
	switch msg.Cmd {
	case circuit.RCmdSession:
		f := cc.onSession
		cc.mu.Unlock()
		if f != nil {
			f(msg.Data)
		}
		return
	case circuit.RCmdIntroduce2:
		f := cc.onIntroduce
		cc.mu.Unlock()
		if f != nil {
			f(msg.Data)
		}
		return
	}
	ch := cc.waiters[msg.Cmd]
	delete(cc.waiters, msg.Cmd)
	cc.mu.Unlock()
	if ch != nil {
		ch <- msg
	}
}

// send seals a relay message for the terminal hop.
func (cc *clientCircuit) send(cmd circuit.RCmd, data []byte) error {
	select {
	case <-cc.done:
		return ErrCircuitClosed
	default:
	}
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	block, err := cc.c.SendRelay(cc.termKeys().Af, &circuit.RelayCell{Cmd: cmd, Data: data})
	if err != nil {
		return err
	}
	return cc.cs.WriteCell(&link.Cell{Circuit: cc.c.ID(), Command: link.CmdRelay, Payload: block})
}

// request sends a command and waits for the reply command.
func (cc *clientCircuit) request(ctx context.Context, cmd circuit.RCmd, data []byte, want circuit.RCmd) (*circuit.RelayCell, error) {
	ch := make(chan *circuit.RelayCell, 1)
	cc.mu.Lock()
	cc.waiters[want] = ch
	cc.mu.Unlock()
	if err := cc.send(cmd, data); err != nil {
		return nil, err
	}
	return cc.await(ctx, ch)
}

// expect registers a wait for a reply that is not a direct answer to a send
// (RENDEZVOUS2 comes when the service answers, not when we ask).
func (cc *clientCircuit) expect(want circuit.RCmd) chan *circuit.RelayCell {
	ch := make(chan *circuit.RelayCell, 1)
	cc.mu.Lock()
	cc.waiters[want] = ch
	cc.mu.Unlock()
	return ch
}

func (cc *clientCircuit) await(ctx context.Context, ch chan *circuit.RelayCell) (*circuit.RelayCell, error) {
	select {
	case m := <-ch:
		return m, nil
	case <-cc.done:
		return nil, ErrCircuitClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (cc *clientCircuit) whenDead(f func()) {
	cc.mu.Lock()
	select {
	case <-cc.done:
		cc.mu.Unlock()
		f()
		return
	default:
	}
	cc.onDeath = append(cc.onDeath, f)
	cc.mu.Unlock()
}

func (cc *clientCircuit) die() {
	cc.once.Do(func() {
		cc.mu.Lock()
		close(cc.done)
		fs := cc.onDeath
		cc.onDeath = nil
		cc.mu.Unlock()
		cc.cs.Close()
		for _, f := range fs {
			f()
		}
	})
}

// close tears the circuit down from this end.
func (cc *clientCircuit) close() {
	cc.wmu.Lock()
	cc.cs.WriteCell(circuit.DestroyCell(cc.c.ID(), circuit.ReasonFinished))
	cc.wmu.Unlock()
	cc.die()
}

// carrier is a session.Carrier over the circuit: SESSION cells to the terminal.
type carrier struct{ cc *clientCircuit }

func (k carrier) Send(p []byte) error { return k.cc.send(circuit.RCmdSession, p) }

// receiveInto routes the circuit's SESSION cells to s and orphans s when the
// circuit dies -- without yet making it s's carrier (see attach).
func (cc *clientCircuit) receiveInto(s *session.Session) carrier {
	k := carrier{cc}
	cc.mu.Lock()
	cc.onSession = func(d []byte) { s.Receive(k, d) }
	cc.mu.Unlock()
	cc.whenDead(func() { s.CarrierLost(k, ErrCircuitClosed) })
	return k
}

// attach makes the circuit carry a session in both directions.
func (cc *clientCircuit) attach(s *session.Session) carrier {
	k := cc.receiveInto(s)
	s.Attach(k)
	return k
}

// ---------------------------------------------------------------- paths

// guardRelay is the pinned first hop: chosen once, kept in DataDir/guard, and
// replaced only when it leaves the directory. A guard that changes with every
// circuit is a fresh chance per circuit to pick a hostile first hop.
func (rt *Runtime) guardRelay(relays []*RelayInfo) *RelayInfo {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	path := filepath.Join(rt.cfg.DataDir, "guard")
	if rt.guard == nil {
		if b, err := os.ReadFile(path); err == nil {
			want := strings.TrimSpace(string(b))
			for _, ri := range relays {
				if ri.Peer.String() == want {
					rt.guard = ri
				}
			}
		}
	}
	if rt.guard != nil {
		for _, ri := range relays {
			if ri.Peer == rt.guard.Peer {
				rt.guard = ri
				return ri
			}
		}
	}
	if len(relays) == 0 {
		return nil
	}
	rt.guard = relays[mrand.IntN(len(relays))]
	os.WriteFile(path, []byte(rt.guard.Peer.String()+"\n"), 0o600)
	return rt.guard
}

// pickPath chooses n relays ending at last (nil: any), excluding exclude and
// this node itself, guard first, one per network prefix unless the config
// allows otherwise.
func (rt *Runtime) pickPath(n int, last *RelayInfo, exclude map[link.NodeID]bool) ([]*RelayInfo, error) {
	var cands []*RelayInfo
	for _, ri := range rt.dir.Relays() {
		if ri.Peer == rt.host.ID() || exclude[ri.Peer] {
			continue
		}
		cands = append(cands, ri)
	}
	if last != nil && last.Peer == rt.host.ID() {
		return nil, errors.New("axon/runtime: a circuit cannot end at this node")
	}
	path := make([]*RelayInfo, 0, n)
	used := map[link.NodeID]bool{}
	prefixes := map[string]bool{}
	take := func(ri *RelayInfo) {
		path = append(path, ri)
		used[ri.Peer] = true
		prefixes[ri.prefix()] = true
	}
	if last != nil {
		used[last.Peer] = true
		prefixes[last.prefix()] = true
	}
	ok := func(ri *RelayInfo) bool {
		if used[ri.Peer] {
			return false
		}
		return rt.cfg.AllowSameNetwork || !prefixes[ri.prefix()]
	}
	if g := rt.guardRelay(cands); g != nil && ok(g) && (last == nil || n > 1) {
		take(g)
	}
	want := n
	if last != nil {
		want = n - 1
	}
	mrand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	for _, ri := range cands {
		if len(path) >= want {
			break
		}
		if ok(ri) {
			take(ri)
		}
	}
	if len(path) < want {
		return nil, ErrTooFewRelay
	}
	if last != nil {
		path = append(path, last)
	}
	return path, nil
}

// circuitTo builds a fresh circuit of the configured length ending at last.
func (rt *Runtime) circuitTo(ctx context.Context, last *RelayInfo, exclude map[link.NodeID]bool) (*clientCircuit, error) {
	var lastErr error
	for attempt := 0; attempt < params.TunnelBuildTries; attempt++ {
		path, err := rt.pickPath(rt.cfg.Hops, last, exclude)
		if err != nil {
			return nil, err
		}
		cctx, cancel := context.WithTimeout(ctx, params.TunnelBuildTimeout)
		cc, err := rt.buildCircuit(cctx, path)
		cancel()
		if err == nil {
			return cc, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("axon/runtime: no circuit after %d tries: %w", params.TunnelBuildTries, lastErr)
}

// ---------------------------------------------------------------- link specs

// A link spec is how an EXTEND names where the next hop is: its libp2p peer id
// and its addresses. The next hop's ntor handshake is what proves the relay
// reached the right one -- a relay that dials an impostor gets ErrWrongKey.
func encodeLinkSpec(ri *RelayInfo) []byte {
	id := []byte(ri.Peer)
	b := binary.BigEndian.AppendUint16(nil, uint16(len(id)))
	b = append(b, id...)
	b = append(b, byte(len(ri.Addrs)))
	for _, a := range ri.Addrs {
		b = append(b, byte(len(a)))
		b = append(b, a...)
	}
	return b
}

func decodeLinkSpec(b []byte) (*RelayInfo, error) {
	bad := errors.New("axon/runtime: malformed link spec")
	if len(b) < 2 {
		return nil, bad
	}
	n := int(binary.BigEndian.Uint16(b))
	if n == 0 || len(b) < 2+n+1 {
		return nil, bad
	}
	id := link.NodeID(b[2 : 2+n])
	if err := id.Validate(); err != nil {
		return nil, bad
	}
	ri := &RelayInfo{Peer: id}
	b = b[2+n:]
	count := int(b[0])
	b = b[1:]
	for i := 0; i < count && i < 8; i++ {
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return nil, bad
		}
		ri.Addrs = append(ri.Addrs, string(b[1:1+int(b[0])]))
		b = b[1+int(b[0]):]
	}
	if len(ri.Addrs) == 0 {
		return nil, bad
	}
	return ri, nil
}
