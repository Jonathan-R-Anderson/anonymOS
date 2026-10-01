package session

import (
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

// The in-memory carrier: two ends of one path, each delivering in order into
// the other session's Receive from its own goroutine, as a circuit's reader
// would. Killing a path loses whatever was in flight on it -- that is what a
// carrier death is, and it is the case T7.2 is about.

var errPathDead = errors.New("test path is dead")

type pathEnd struct {
	p     *path
	to    *Session
	other *pathEnd
	q     chan []byte
}

type path struct {
	mu     sync.Mutex
	dead   bool
	silent bool // a silent death: sends vanish, nothing is reported
	stop   chan struct{}
	cli    *pathEnd // the client's carrier (delivers to the service)
	svc    *pathEnd // the service's carrier (delivers to the client)
	// tamper, when set, may rewrite or drop (return nil) a packet in flight.
	// dir is 0 client→service, 1 service→client. It is the hostile RP.
	tamper func(dir int, p []byte) []byte
	// inject delivers a packet to one side as if it came off this path.
	delivered [2]int
}

func (e *pathEnd) Send(p []byte) error {
	e.p.mu.Lock()
	dead, silent := e.p.dead, e.p.silent
	e.p.mu.Unlock()
	if dead {
		if silent {
			return nil
		}
		return errPathDead
	}
	cp := append([]byte(nil), p...)
	select {
	case e.q <- cp:
		return nil
	case <-e.p.stop:
		if silent {
			return nil
		}
		return errPathDead
	}
}

func (e *pathEnd) pump(dir int) {
	for {
		select {
		case <-e.p.stop:
			return
		case pk := <-e.q:
			e.p.mu.Lock()
			dead, tamper := e.p.dead, e.p.tamper
			e.p.mu.Unlock()
			if dead {
				continue
			}
			if tamper != nil {
				if pk = tamper(dir, pk); pk == nil {
					continue
				}
			}
			_ = e.to.Receive(e.other, pk)
			e.p.mu.Lock()
			e.p.delivered[dir]++
			e.p.mu.Unlock()
		}
	}
}

// connect builds a path and attaches both ends to it, service first (its side
// of the rendezvous exists before the client's splice completes).
func connect(t testing.TB, cli, svc *Session) *path {
	p := &path{stop: make(chan struct{})}
	p.cli = &pathEnd{p: p, to: svc, q: make(chan []byte, 8192)}
	p.svc = &pathEnd{p: p, to: cli, q: make(chan []byte, 8192)}
	p.cli.other, p.svc.other = p.svc, p.cli
	go p.cli.pump(0)
	go p.svc.pump(1)
	if err := svc.Attach(p.svc); err != nil {
		t.Errorf("service attach: %v", err)
	}
	if err := cli.Attach(p.cli); err != nil {
		t.Errorf("client attach: %v", err)
	}
	return p
}

// kill ends the path. An explicit death is reported to both sessions, as a
// DESTROY or TRUNCATED would be; a silent one is reported to nobody.
func (p *path) kill(explicit bool) {
	p.mu.Lock()
	if p.dead {
		p.mu.Unlock()
		return
	}
	p.dead, p.silent = true, !explicit
	close(p.stop)
	p.mu.Unlock()
	if explicit {
		p.cli.to.CarrierLost(p.svc, errPathDead) // the service's carrier
		p.svc.to.CarrierLost(p.cli, errPathDead) // the client's carrier
	}
}

func testConfig() Config {
	c := DefaultConfig()
	c.MinRTO = 50 * time.Millisecond
	c.MaxRTO = 400 * time.Millisecond
	c.ProbeTimeout = 600 * time.Millisecond
	c.AckDelay = 2 * time.Millisecond
	c.OrphanRetention = 10 * time.Second
	c.IdleTimeout = time.Minute
	c.HardLifetime = 10 * time.Minute
	return c
}

func seed(t testing.TB) (s [32]byte) {
	if _, err := rand.Read(s[:]); err != nil {
		t.Fatal(err)
	}
	return s
}

// pair builds a client and service session over one fresh path. The client's
// OnOrphan builds a replacement path after `replace`, as a tunnel pool with a
// READY spare would; cur always holds the live path.
type pairT struct {
	cli, svc *Session
	mu       sync.Mutex
	cur      *path
	paths    int
}

func (pr *pairT) path() *path {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return pr.cur
}

func newPair(t testing.TB, cfg Config, replace time.Duration) *pairT {
	t.Helper()
	pr := &pairT{}
	k := seed(t)
	ccfg := cfg
	ccfg.OnOrphan = func(s *Session, why error) {
		time.Sleep(replace)
		if s.State() != Orphaned {
			return
		}
		p := connect(t, pr.cli, pr.svc)
		pr.mu.Lock()
		pr.cur = p
		pr.paths++
		pr.mu.Unlock()
	}
	var err error
	pr.cli, err = NewClient(k, ccfg)
	if err != nil {
		t.Fatal(err)
	}
	pr.svc = NewService(k, pr.cli.ID(), cfg)
	pr.cur = connect(t, pr.cli, pr.svc)
	pr.paths = 1
	t.Cleanup(func() {
		pr.cli.Close()
		pr.svc.Close()
		pr.path().kill(false)
	})
	return pr
}

func cryptoRead(b []byte) (int, error) { return rand.Read(b) }
