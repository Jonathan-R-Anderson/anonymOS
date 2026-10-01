package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Crash intake (roadmap §5).  Reports arrive through AXON, already scrubbed on the computer; this
// side re-checks them against a whitelist schema -- any field it does not know is refused, not
// stored -- so a client bug cannot leak something the scrubber missed into the archive.  Stored as
// JSON lines (crashes/YYYY-MM-DD.jsonl), grouped by signature for the operator's view.

const maxCrashBody = 16 << 10

var (
	reProgram  = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	reBuildID  = regexp.MustCompile(`^[0-9a-f]{0,64}$`)
	reVersion  = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,32}$`)
	reFrame    = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}\+0x[0-9a-f]{1,16}$`)
	reReportID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	crashKinds = map[string]bool{"segfault": true, "exception": true, "abort": true, "signal": true,
		"kernel-fault": true, "kernel-panic": true, "compositor-died": true}
)

// CrashReport is the whole schema.  Nothing that identifies a computer or a person fits in it.
type CrashReport struct {
	ReportID  string   `json:"report_id"`  // fresh random per report: two reports are unlinkable
	OSVersion string   `json:"os_version"` // e.g. "0.2.0"
	Program   string   `json:"program"`    // the executable's basename
	BuildID   string   `json:"build_id"`   // the binary's build id, hex (empty when unknown)
	Kind      string   `json:"kind"`
	Code      int      `json:"code"`   // exit code / signal / exception vector
	Frames    []string `json:"frames"` // "<module>+0x<offset>", innermost first, at most 32
	UptimeMin int      `json:"uptime_min"`
}

func (r *CrashReport) validate() string {
	switch {
	case !reReportID.MatchString(r.ReportID):
		return "report_id"
	case !reVersion.MatchString(r.OSVersion):
		return "os_version"
	case !reProgram.MatchString(r.Program):
		return "program"
	case !reBuildID.MatchString(r.BuildID):
		return "build_id"
	case !crashKinds[r.Kind]:
		return "kind"
	case r.Code < -1 || r.Code > 1<<16:
		return "code"
	case len(r.Frames) > 32:
		return "frames"
	case r.UptimeMin < 0 || r.UptimeMin > 1<<20:
		return "uptime_min"
	}
	for _, f := range r.Frames {
		if !reFrame.MatchString(f) {
			return "frames"
		}
	}
	return ""
}

// Signature groups reports of the same crash: program, build and the top frames.
func (r *CrashReport) Signature() string {
	top := r.Frames
	if len(top) > 5 {
		top = top[:5]
	}
	h := sha256.Sum256([]byte(r.Program + "\x00" + r.BuildID + "\x00" + r.Kind + "\x00" + strings.Join(top, "\x00")))
	return hex.EncodeToString(h[:8])
}

type crashGroup struct {
	Signature string   `json:"signature"`
	Program   string   `json:"program"`
	Kind      string   `json:"kind"`
	TopFrames []string `json:"top_frames"`
	Count     int      `json:"count"`
	Versions  []string `json:"os_versions"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
}

type CrashIntake struct {
	store  *Store
	mu     sync.Mutex
	groups map[string]*crashGroup
	seen   map[string]time.Time // report_id dedupe (a retried send is not two crashes)
}

func NewCrashIntake(store *Store) *CrashIntake {
	c := &CrashIntake{store: store, groups: map[string]*crashGroup{}, seen: map[string]time.Time{}}
	var saved []*crashGroup
	if store.LoadJSON("crash-groups.json", &saved) == nil {
		for _, g := range saved {
			c.groups[g.Signature] = g
		}
	}
	return c
}

func (c *CrashIntake) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/crash", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r, maxCrashBody)
		if err != nil {
			writeJSON(w, 413, map[string]string{"error": "report too large"})
			return
		}
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields() // a field the schema does not name is refused, never stored
		var rep CrashReport
		if err := dec.Decode(&rep); err != nil {
			writeJSON(w, 400, map[string]string{"error": "not a crash report"})
			return
		}
		if bad := rep.validate(); bad != "" {
			writeJSON(w, 400, map[string]string{"error": "invalid field: " + bad})
			return
		}
		now := time.Now().UTC()
		c.mu.Lock()
		if _, dup := c.seen[rep.ReportID]; dup {
			c.mu.Unlock()
			writeJSON(w, 200, map[string]any{"ok": true, "duplicate": true})
			return
		}
		c.seen[rep.ReportID] = now
		for id, t := range c.seen {
			if now.Sub(t) > 7*24*time.Hour {
				delete(c.seen, id)
			}
		}
		sig := rep.Signature()
		g := c.groups[sig]
		if g == nil {
			top := rep.Frames
			if len(top) > 5 {
				top = top[:5]
			}
			g = &crashGroup{Signature: sig, Program: rep.Program, Kind: rep.Kind, TopFrames: top,
				FirstSeen: now.Format(time.RFC3339)}
			c.groups[sig] = g
		}
		g.Count++
		g.LastSeen = now.Format(time.RFC3339)
		if !contains(g.Versions, rep.OSVersion) {
			g.Versions = append(g.Versions, rep.OSVersion)
		}
		snapshot := c.snapshotLocked()
		c.mu.Unlock()
		_ = c.store.AppendLine("crashes-"+now.Format("2006-01-02")+".jsonl", rep)
		_ = c.store.SaveJSON("crash-groups.json", snapshot)
		writeJSON(w, 200, map[string]any{"ok": true, "signature": sig})
	})
	// The operator's view, meant to be read on the VPS.  A request that came in through the
	// network (the AXON service's listener marks its connections, see viaNetwork) is refused.
	mux.HandleFunc("GET /api/v1/crash/groups", func(w http.ResponseWriter, r *http.Request) {
		if viaNetwork(r) {
			writeJSON(w, 403, map[string]string{"error": "operator view is local only"})
			return
		}
		c.mu.Lock()
		out := c.snapshotLocked()
		c.mu.Unlock()
		writeJSON(w, 200, out)
	})
}

func (c *CrashIntake) snapshotLocked() []*crashGroup {
	out := make([]*crashGroup, 0, len(c.groups))
	for _, g := range c.groups {
		cp := *g
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

type networkConnKey struct{}

// MarkNetwork is the http.Server ConnContext for the listener that carries requests arriving
// through the dendritic network: handlers meant only for the operator refuse those requests.
func MarkNetwork(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, networkConnKey{}, true)
}

func viaNetwork(r *http.Request) bool {
	v, _ := r.Context().Value(networkConnKey{}).(bool)
	return v
}
