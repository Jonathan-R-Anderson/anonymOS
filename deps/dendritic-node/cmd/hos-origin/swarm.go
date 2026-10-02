package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/swarm"
)

// The origin's part in the swarm (roadmap §4, "Release push"): it is the
// TRACKER that introduces the nodes fetching one file to each other, and the
// first SEEDER of every file it publishes. It is deliberately not the main
// source: it super-seeds, so its upload goes into pieces the swarm lacks, and
// the nodes do the rest between themselves (internal/axon/swarm says why that is
// faster than any one server, and by how much).
//
// Artifacts live content-addressed under <state>/artifacts/<sha256>; each is
// seeded under its Merkle root, whose locator is what a release manifest lists.

const (
	// announceInterval is what the tracker asks members to re-announce at; an
	// entry not renewed within three of them is dropped.
	announceInterval = 30 * time.Second
	maxSwarmMembers  = 4096
	maxPeersReturned = 50
)

var (
	reRoot     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePeerAddr = regexp.MustCompile(`^[a-z0-9][a-z0-9.:-]{0,127}$`)
)

type member struct {
	complete bool
	seen     time.Time
}

// Tracker is swarm membership: per file root, the AXON addresses of the nodes in
// it. It holds nothing but those addresses, which are service addresses the
// nodes publish anyway, and forgets them after three missed announces.
type Tracker struct {
	mu      sync.Mutex
	swarms  map[[32]byte]map[swarm.PeerAddr]*member
	seeds   map[[32]byte]bool // roots this origin seeds itself
	self    swarm.PeerAddr    // the origin's own AXON address, if configured
	nowFunc func() time.Time
}

func NewTracker(self swarm.PeerAddr) *Tracker {
	return &Tracker{swarms: map[[32]byte]map[swarm.PeerAddr]*member{}, seeds: map[[32]byte]bool{},
		self: self, nowFunc: time.Now}
}

func (t *Tracker) announce(root [32]byte, addr swarm.PeerAddr, complete bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.swarms[root]
	if m == nil {
		m = map[swarm.PeerAddr]*member{}
		t.swarms[root] = m
	}
	if _, ok := m[addr]; !ok && len(m) >= maxSwarmMembers {
		t.expireLocked(root)
		if len(m) >= maxSwarmMembers {
			return fmt.Errorf("swarm full")
		}
	}
	m[addr] = &member{complete: complete, seen: t.nowFunc()}
	return nil
}

func (t *Tracker) expireLocked(root [32]byte) {
	cut := t.nowFunc().Add(-3 * announceInterval)
	for a, m := range t.swarms[root] {
		if m.seen.Before(cut) {
			delete(t.swarms[root], a)
		}
	}
}

// peers returns up to max members other than exclude, at random -- with the
// origin first when it seeds this file, so every new node reaches the one
// source guaranteed to have every piece.
func (t *Tracker) peers(root [32]byte, max int, exclude swarm.PeerAddr) []swarm.PeerAddr {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(root)
	var out []swarm.PeerAddr
	for a := range t.swarms[root] {
		if a != exclude && a != t.self {
			out = append(out, a)
		}
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	if t.seeds[root] && t.self != "" && exclude != t.self {
		out = append([]swarm.PeerAddr{t.self}, out...)
	}
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func parseRoot(s string) ([32]byte, bool) {
	var r [32]byte
	if !reRoot.MatchString(s) {
		return r, false
	}
	b, _ := hex.DecodeString(s)
	copy(r[:], b)
	return r, true
}

// Register adds the tracker's endpoints:
//
//	POST /api/v1/swarm/{root}/announce   {"addr": "...", "complete": bool}
//	GET  /api/v1/swarm/{root}/peers?max=N&exclude=<addr>
//	GET  /api/v1/swarm                   the files this origin seeds, as locators
func (t *Tracker) Register(mux *http.ServeMux, seeder *Seeder) {
	mux.HandleFunc("POST /api/v1/swarm/{root}/announce", func(w http.ResponseWriter, r *http.Request) {
		root, ok := parseRoot(r.PathValue("root"))
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "invalid root"})
			return
		}
		body, err := readBody(r, 1024)
		if err != nil {
			writeJSON(w, 413, map[string]string{"error": "too large"})
			return
		}
		var req struct {
			Addr     string `json:"addr"`
			Complete bool   `json:"complete"`
		}
		if json.Unmarshal(body, &req) != nil || !rePeerAddr.MatchString(req.Addr) {
			writeJSON(w, 400, map[string]string{"error": "invalid announce"})
			return
		}
		if err := t.announce(root, swarm.PeerAddr(req.Addr), req.Complete); err != nil {
			writeJSON(w, 503, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"interval": int(announceInterval / time.Second)})
	})
	mux.HandleFunc("GET /api/v1/swarm/{root}/peers", func(w http.ResponseWriter, r *http.Request) {
		root, ok := parseRoot(r.PathValue("root"))
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "invalid root"})
			return
		}
		max, _ := strconv.Atoi(r.URL.Query().Get("max"))
		if max <= 0 || max > maxPeersReturned {
			max = maxPeersReturned
		}
		ps := t.peers(root, max, swarm.PeerAddr(r.URL.Query().Get("exclude")))
		if ps == nil {
			ps = []swarm.PeerAddr{}
		}
		noStore(w)
		writeJSON(w, 200, map[string]any{"peers": ps})
	})
	mux.HandleFunc("GET /api/v1/swarm", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"seeding": seeder.Locators()})
	})
}

// Seeder super-seeds every artifact in <state>/artifacts.
type Seeder struct {
	Host    *swarm.Host
	tracker *Tracker
	mu      sync.Mutex
	files   map[string]swarm.Meta // artifact file name -> its swarm
	open    []*os.File
}

func NewSeeder(t *Tracker) *Seeder {
	return &Seeder{Host: swarm.NewHost(), tracker: t, files: map[string]swarm.Meta{}}
}

// Load seeds every artifact under dir (re-runnable: already-seeded files are
// skipped). Hashing a file is the cost; it is paid once per file per start.
func (s *Seeder) Load(dir string) error {
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		s.mu.Lock()
		_, done := s.files[e.Name()]
		s.mu.Unlock()
		if done {
			continue
		}
		if err := s.seed(filepath.Join(dir, e.Name())); err != nil {
			log.Printf("hos-origin: not seeding %s: %v", e.Name(), err)
		}
	}
	return nil
}

func (s *Seeder) seed(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		f.Close()
		return fmt.Errorf("empty or unreadable")
	}
	tree, err := swarm.BuildTree(f, st.Size(), swarm.DefaultPieceSize)
	if err != nil {
		f.Close()
		return err
	}
	sw, err := swarm.New(swarm.Config{Tree: tree, Storage: readOnly{f}, SuperSeed: true})
	if err != nil {
		f.Close()
		return err
	}
	s.Host.Add(sw)
	s.tracker.mu.Lock()
	s.tracker.seeds[tree.Meta().Root] = true
	s.tracker.mu.Unlock()
	s.mu.Lock()
	s.files[filepath.Base(path)] = tree.Meta()
	s.open = append(s.open, f)
	s.mu.Unlock()
	log.Printf("hos-origin: seeding %s as %s", filepath.Base(path), tree.Meta().Locator())
	return nil
}

// Locators lists what is seeded: file name -> axon-swarm locator.
func (s *Seeder) Locators() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	names := make([]string, 0, len(s.files))
	for n := range s.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out[n] = s.files[n].Locator()
	}
	return out
}

// readOnly is a seeded artifact: the origin serves it and never writes it.
type readOnly struct{ f *os.File }

func (r readOnly) ReadAt(p []byte, off int64) (int, error) { return r.f.ReadAt(p, off) }
func (r readOnly) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("hos-origin: a seeded artifact is read-only")
}
