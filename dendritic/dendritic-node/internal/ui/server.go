package ui

import (
	"context"
	_ "embed"

	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// The site's own logo, compiled into the binary. Embedded rather than fetched
// because this node runs behind I2P and must never reach the web server for an
// asset -- and a volunteer's dashboard should not phone home to render.
//
//go:embed icon.png
var IconPNG []byte

type NodeInfo interface {
	ID() string
	Addresses() []string
	// PeerCount is a live gauge: volunteers are dial-in only, so it falls to
	// zero whenever a connection lapses and recovers on the next retry.
	PeerCount() int
}

type Server struct {
	store    *store.Store
	node     NodeInfo
	csrf     string
	logger   *log.Logger
	template *template.Template
	dataDir  string
	saveDir  func(string) error
	// meter drives the live load graph. Nil when compute is off — the panel is
	// then absent rather than showing an empty chart, because a graph of
	// nothing invites the reader to conclude the machine is idle when in fact
	// nothing is measuring it.
	meter *LoadMeter
	// network reports compute peers this node learned from bootstrap. A func
	// rather than a value so the UI always reads the CURRENT listing rather
	// than one captured when the server started.
	network func() any
	// Config access (wired by main). Without it the config panels are absent.
	cfgSnapshot func() config.Config
	cfgApply    func(func(*config.Config) error) error
	// listen is the address this page is served on, and it is what decides
	// whether a password is demanded -- the server asks where it is bound
	// rather than being told whether to authenticate. The two cannot then
	// disagree: there is no way to wire up a LAN-reachable dashboard and forget
	// to turn authentication on.
	listen string
	// listenIsUnspecified: bound to 0.0.0.0 or ::, so there is no single
	// address a browser's Host header could match. See validRequestHost.
	listenIsUnspecified bool
	// SHA-256 of the expected credential. Digests rather than the strings
	// themselves so the comparison is over fixed-length values: a byte-wise
	// compare of the raw password would take a length-dependent amount of time
	// and leak how long the password is even when constant-time within a
	// length. authSet distinguishes "no password configured" from "the password
	// is the empty string", which must never be accepted.
	authUser, authPass [sha256.Size]byte
	authSet            bool

	// receiving is the payment node, when this one accepts tips. Nil on a
	// storage-only node, and the receiving routes answer 501 then.
	receiving Receiving
}

// SetAccessControl tells the dashboard where it is bound and what credential to
// demand. Bound to loopback, the credential is ignored and the page behaves as
// it always has. Bound anywhere else, every request must carry it -- and if
// none was configured the page refuses to serve at all rather than opening the
// node's settings to the network. Kept off New() so existing callers and tests
// are unaffected; a Server nobody called this on is loopback-only.
func (s *Server) SetAccessControl(listen, username, password string) {
	s.listen = listen
	s.listenIsUnspecified = false
	if host, _, err := net.SplitHostPort(listen); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.IsUnspecified() {
			s.listenIsUnspecified = true
		}
	}
	s.authSet = password != ""
	s.authUser = sha256.Sum256([]byte(username))
	s.authPass = sha256.Sum256([]byte(password))
}

// reachableFromNetwork reports whether this page is served anywhere other than
// loopback. An empty listen address means the caller never said, which happens
// only in tests and in-process uses that are loopback by construction.
func (s *Server) reachableFromNetwork() bool {
	return s.listen != "" && !config.ListenIsLoopback(s.listen)
}

// authorize gates every request when the page is not on loopback.
//
// It runs before anything else, including the host check, so that a caller
// without the password cannot learn anything from the difference between one
// rejection and another.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	if !s.reachableFromNetwork() {
		return true
	}
	if !s.authSet {
		// Config validation refuses this combination, so reaching here means
		// something bypassed it. Fail closed: an admin page with no password on
		// a network is worse than no admin page.
		http.Error(w, "the management dashboard is bound to a network address but no "+
			"ui_password is set; it will not serve until one is configured",
			http.StatusServiceUnavailable)
		return false
	}
	user, password, ok := r.BasicAuth()
	if ok {
		userDigest := sha256.Sum256([]byte(user))
		passwordDigest := sha256.Sum256([]byte(password))
		// Bitwise & rather than && so both comparisons always run: a
		// short-circuit here would answer a wrong username faster than a wrong
		// password and turn the username into something worth probing for.
		match := subtle.ConstantTimeCompare(userDigest[:], s.authUser[:]) &
			subtle.ConstantTimeCompare(passwordDigest[:], s.authPass[:])
		if match == 1 {
			return true
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Syndichan node", charset="UTF-8"`)
	http.Error(w, "the management dashboard requires the ui_username and ui_password "+
		"from this node's config file", http.StatusUnauthorized)
	return false
}

// validRequestHost is validDashboardHost plus the address this page was
// deliberately bound to. The rebinding defence is unchanged in substance: an
// attacker's domain still does not match, because the check is an exact match
// against a literal address the operator chose, never a name lookup.
func (s *Server) validRequestHost(value string) bool {
	if validDashboardHost(value) {
		return true
	}
	if s.listen != "" && strings.EqualFold(value, s.listen) {
		return true
	}
	// Bound to every interface (0.0.0.0 / ::), which is the default. There is no
	// single address to compare against -- the operator reaches this page at
	// whichever of the machine's addresses they can route to, and the node
	// cannot know which -- so the literal-address check above matches nothing
	// real and every LAN request was rejected as an "invalid dashboard host".
	//
	// Accept any IP-LITERAL Host instead. That keeps the guard doing the one job
	// it exists for: DNS rebinding needs a NAME in the Host header, because the
	// attack is a hostname whose address flips to a private one after the page
	// loads. An IP literal cannot rebind -- there is nothing to re-resolve -- so
	// allowing them costs nothing, while a name still has to pass
	// validDashboardHost.
	if s.listenIsUnspecified {
		host := value
		if h, _, err := net.SplitHostPort(value); err == nil {
			host = h
		}
		return net.ParseIP(strings.Trim(host, "[]")) != nil
	}
	return false
}

// SetStoragePaths tells the dashboard where shards live and how to persist a
// change. Kept off New() so existing callers and tests are unaffected.
func (s *Server) SetStoragePaths(dataDir string, save func(string) error) {
	s.dataDir = dataDir
	s.saveDir = save
}

func New(storage *store.Store, node NodeInfo, logger *log.Logger) *Server {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		panic(err)
	}
	return &Server{
		store: storage, node: node,
		csrf: base64.RawURLEncoding.EncodeToString(tokenBytes), logger: logger,
		template: template.Must(template.New("dashboard").Parse(pageHTML)),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if !s.validRequestHost(r.Host) {
		http.Error(w, "invalid dashboard host", http.StatusMisdirectedRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		s.dashboard(w, r)
	case r.URL.Path == "/favicon.png" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(IconPNG)
	case r.URL.Path == "/api/network" && r.Method == http.MethodGet:
		s.serveNetwork(w, r)
	case r.URL.Path == "/api/load" && r.Method == http.MethodGet:
		if s.meter != nil {
			s.meter.ServeHTTP(w, r)
			return
		}
		http.Error(w, "load meter unavailable", http.StatusServiceUnavailable)
	case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
		s.status(w)
	case r.URL.Path == "/api/items" && r.Method == http.MethodGet:
		s.items(w)
	case r.URL.Path == "/reject" && r.Method == http.MethodPost:
		s.reject(w, r)
	case r.URL.Path == "/capacity" && r.Method == http.MethodPost:
		s.setCapacity(w, r)
	case r.URL.Path == "/storage-dir" && r.Method == http.MethodPost:
		s.setStorageDir(w, r)
	case r.URL.Path == "/config/mode" && r.Method == http.MethodPost:
		s.setRunMode(w, r)
	case r.URL.Path == "/config/gateway" && r.Method == http.MethodPost:
		s.setGateway(w, r)
	case r.URL.Path == "/config/storage" && r.Method == http.MethodPost:
		s.setStorageSettings(w, r)
	case r.URL.Path == "/config/router" && r.Method == http.MethodPost:
		s.setRouter(w, r)
	case r.URL.Path == "/config/compute" && r.Method == http.MethodPost:
		s.setCompute(w, r)
	case r.URL.Path == "/config/dcs" && r.Method == http.MethodPost:
		s.setDCS(w, r)
	case r.URL.Path == "/config/payout" && r.Method == http.MethodPost:
		s.setPayout(w, r)
	case r.URL.Path == "/api/receiving" && r.Method == http.MethodGet:
		s.serveReceiving(w, r)
	case r.URL.Path == "/api/tips" && r.Method == http.MethodGet:
		s.serveTips(w, r)
	case r.URL.Path == "/tips/accept" && r.Method == http.MethodPost:
		s.acceptTip(w, r)
	case r.URL.Path == "/tips/publish" && r.Method == http.MethodPost:
		s.publishTip(w, r)
	case r.URL.Path == "/receiving/policy" && r.Method == http.MethodPost:
		s.setReceivingPolicy(w, r)
	case r.URL.Path == "/receiving/settle" && r.Method == http.MethodPost:
		s.settleReceiving(w, r)
	case r.URL.Path == "/receiving/close" && r.Method == http.MethodPost:
		s.closeReceiving(w, r)
	default:
		http.NotFound(w, r)
	}
}

// validDashboardHost is the DNS-rebinding defence: a page that only ever
// answers to a literal local address cannot be reached by a hostile site that
// points its own domain at this machine.
func validDashboardHost(value string) bool {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"CSRF": s.csrf, "HasConfig": s.hasConfig()}
	// Absent rather than empty when this node does not receive: a panel showing
	// no channels reads as "nobody has tipped you", which is a different and
	// discouraging claim from "this node is not set up to receive".
	if s.receiving != nil {
		if channels, err := s.receiving.Channels(context.Background()); err == nil {
			data["Receiving"] = channels
		}
		// Waiting tips (P15). The ERROR is carried, not discarded: a panel that
		// fell back to an empty list would tell a recipient whose authorization
		// had lapsed that nobody has tipped them.
		data["TipsOn"] = true
		if tips, err := s.receiving.WaitingTips(context.Background()); err != nil {
			data["TipsError"] = err.Error()
		} else {
			data["Tips"] = tips
		}
		if q := r.URL.Query(); q.Get("tip") != "" {
			data["TipOutcome"] = q.Get("tip")
			data["TipDetail"] = q.Get("detail")
		}
	}
	if s.hasConfig() {
		c := s.cfgSnapshot()
		data["Cfg"] = c
		data["Mode"] = c.ResolvedRole()
		data["RAMGiB"] = strconv.FormatFloat(float64(c.DCS.Limits.RAMBytes)/(1<<30), 'f', -1, 64)
		data["Brokers"] = strings.Join(c.DCS.Policy.TrustedBrokers, "\n")
		data["PayoutAddress"] = c.PayoutAddress
	}
	_ = s.template.Execute(w, data)
}

func (s *Server) status(w http.ResponseWriter) {
	// The store is absent in gateway-only / probe-only mode; report node-only
	// stats then, so the management page still works for configuring those roles.
	out := map[string]any{
		"node_id": nodeID(s.node), "addresses": nodeAddrs(s.node),
		"peers": nodePeers(s.node), "i2p_address": i2pAddress(nodeAddrs(s.node)),
		"data_dir": s.dataDir, "has_store": s.store != nil,
	}
	if s.store != nil {
		used, _ := s.store.UsedBytes()
		out["used_bytes"] = used
		out["capacity_bytes"] = s.store.Capacity()
	}
	s.drainStatus(out)
	writeJSON(w, out)
}

// drainStatus is "may I switch this machine off", answered for the page and for
// anything scripting against /api/status.
//
// Absent rather than false when the node is not draining, and the counts are
// separate from the verdict on purpose: safe_to_stop is only ever true when both
// halves are known AND both are zero, so a read error can never round down into
// permission to unplug.
func (s *Server) drainStatus(out map[string]any) {
	node, ok := s.node.(interface{ Draining() bool })
	if !ok || node == nil || !node.Draining() {
		return
	}
	out["draining"] = true
	if s.store == nil {
		return
	}
	held, heldErr := s.store.HeldForOthers()
	summary, summaryErr := s.store.PlacementStatus()
	if heldErr != nil {
		out["drain_held_unknown"] = true
	} else {
		out["drain_shards_held"] = held.Shards
		out["drain_bytes_held"] = held.Bytes
	}
	if summaryErr == nil {
		out["drain_objects"] = summary.Objects
		out["drain_under_replicated"] = summary.UnderReplicated
	}
	out["drain_safe_to_stop"] = heldErr == nil && summaryErr == nil &&
		held.Shards == 0 && summary.UnderReplicated == 0
}

// The node is nil in no-storage-with-file-identity paths; keep the page alive.
func nodeID(n NodeInfo) string {
	if n == nil {
		return ""
	}
	return n.ID()
}
func nodeAddrs(n NodeInfo) []string {
	if n == nil {
		return nil
	}
	return n.Addresses()
}
func nodePeers(n NodeInfo) int {
	if n == nil {
		return 0
	}
	return n.PeerCount()
}

func (s *Server) setCapacity(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return
	}
	if s.store == nil {
		http.Error(w, "no shard store in this run mode", http.StatusBadRequest)
		return
	}
	gib, err := strconv.ParseFloat(r.FormValue("capacity_gib"), 64)
	if err != nil || math.IsNaN(gib) || math.IsInf(gib, 0) || gib <= 0 ||
		gib > float64(store.MaxCapacityBytes)/(1<<30) {
		http.Error(w, "invalid storage allocation", http.StatusBadRequest)
		return
	}
	capacity := int64(math.Round(gib * (1 << 30)))
	if err := s.store.SetCapacity(capacity); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("user changed storage allocation to %d bytes", capacity)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) items(w http.ResponseWriter) {
	if s.store == nil {
		writeJSON(w, map[string]any{"items": []any{}})
		return
	}
	items, err := s.store.ListStored()
	if err != nil {
		http.Error(w, "could not list stored data", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return
	}
	kind, id := r.FormValue("kind"), r.FormValue("id")
	if err := s.store.RejectAndRemove(kind, id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("user rejected stored %s %s", kind, id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// i2pAddress pulls the .b32.i2p host out of a /garlic32/<b32>/p2p/<id>
// multiaddr, which is the form a person can actually read and share.
func i2pAddress(addresses []string) string {
	for _, address := range addresses {
		parts := strings.Split(address, "/")
		for index, part := range parts {
			if part == "garlic32" && index+1 < len(parts) && parts[index+1] != "" {
				return parts[index+1] + ".b32.i2p"
			}
		}
	}
	return ""
}

func (s *Server) setStorageDir(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return
	}
	if s.saveDir == nil {
		http.Error(w, "storage location is not configurable here", http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(r.FormValue("data_dir"))
	if target == "" || !filepath.IsAbs(target) {
		http.Error(w, "enter an absolute path", http.StatusBadRequest)
		return
	}
	// Persist only. The shard store and its bolt database are OPEN right now;
	// moving them under a running process risks corrupting both, so the change
	// takes effect on the next start and the page says so.
	if err := s.saveDir(target); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.logger.Printf("user set storage location to %s (effective next start)", target)
	http.Redirect(w, r, "/?moved=1", http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

const pageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Syndichan Storage Node</title>
<link rel="icon" type="image/png" href="/favicon.png">
<style>
/* Palette mirrors the site's dark themes and uses the same --sc-* naming
   convention. It is duplicated rather than imported on purpose: this node runs
   offline behind I2P and must never reach out to the web server for an asset. */
:root{
  --sc-bg:#0e1116; --sc-panel:#161b22; --sc-panel-2:#1b2230; --sc-border:#2b3440;
  --sc-fg:#d7e0ea; --sc-muted:#8b9bad; --sc-accent:#4ba3e3; --sc-accent-dim:#2b6ea3;
  --sc-ok:#3fa45e; --sc-danger:#a72b3a; --sc-warn:#c9922f;
  --sc-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--sc-bg);color:var(--sc-fg);
  font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{background:var(--sc-panel);border-bottom:1px solid var(--sc-border);padding:14px 20px}
header .wrap{max-width:1060px;margin:auto;display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
header h1{margin:0;font-size:1.15rem;letter-spacing:.02em}
header .tag{color:var(--sc-muted);font-size:.85rem}
main{max-width:1060px;margin:auto;padding:20px}
.panel{background:var(--sc-panel);border:1px solid var(--sc-border);border-radius:8px;
  padding:16px 18px;margin:0 0 16px}
.panel h2{margin:0 0 4px;font-size:1rem;color:var(--sc-fg)}
/* Collapsible panel (a <details>): the shard list can grow long, so it folds. */
details.panel>summary.panel-summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;user-select:none}
details.panel>summary.panel-summary::-webkit-details-marker{display:none}
details.panel>summary.panel-summary::before{content:"\25be";color:var(--sc-muted)}
details.panel:not([open])>summary.panel-summary::before{content:"\25b8"}
details.panel>summary.panel-summary h2{margin:0}
.muted{color:var(--sc-muted);font-size:.9rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:12px}
.stat{background:var(--sc-panel-2);border:1px solid var(--sc-border);border-radius:6px;padding:12px}
.stat .k{color:var(--sc-muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
.stat .v{font-size:1.5rem;margin-top:2px}
.stat .v.small{font-size:.95rem;font-family:var(--sc-mono);word-break:break-all;line-height:1.35}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:baseline}
.dot.on{background:var(--sc-ok)}.dot.off{background:var(--sc-danger)}
.bar{height:10px;background:var(--sc-panel-2);border:1px solid var(--sc-border);
  border-radius:6px;overflow:hidden;margin-top:8px}
.bar span{display:block;height:100%;background:var(--sc-accent)}
form{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
input,select,textarea{background:var(--sc-bg);color:var(--sc-fg);border:1px solid var(--sc-border);
  border-radius:5px;padding:7px 9px;font:inherit}
textarea{width:100%;min-height:4.5rem;font-family:var(--sc-mono);font-size:.85rem}
.cfg label{display:flex;flex-direction:column;gap:4px;font-size:.82rem;color:var(--sc-muted)}
.cfg .row{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;width:100%}
.cfg .chk{flex-direction:row;align-items:center;gap:8px;color:var(--sc-fg)}
.cfg .chk input{width:auto}
.eff{color:var(--sc-warn);font-size:.8rem;margin-top:6px}
input[type=number]{width:9rem}input[name=data_dir]{flex:1;min-width:16rem;font-family:var(--sc-mono);font-size:.9rem}
button{border:0;border-radius:5px;padding:8px 12px;cursor:pointer;font:inherit;color:#fff;
  background:var(--sc-accent-dim)}
button:hover{background:var(--sc-accent)}
button.danger{background:var(--sc-danger)}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--sc-border);vertical-align:top}
th{color:var(--sc-muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}
td code{font-family:var(--sc-mono);font-size:.82rem;color:var(--sc-muted);word-break:break-all}
.notice{border-left:3px solid var(--sc-warn);background:var(--sc-panel-2);padding:9px 12px;
  border-radius:0 5px 5px 0;margin-top:10px;font-size:.9rem}
.copy{background:transparent;border:1px solid var(--sc-border);color:var(--sc-muted);padding:3px 8px;font-size:.78rem}
@media(max-width:560px){.stat .v{font-size:1.2rem}}
</style>
</head>
<body>
<header><div class="wrap"><img src="/favicon.png" alt="" width="24" height="24" style="border-radius:4px"><h1>Syndichan</h1><span class="tag">Storage Node</span></div></header>
<main>
<p class="muted">Only encrypted shards are stored here. Nothing is readable without the
site's keys, and rejecting an item deletes its bytes and refuses that content ID in future.</p>

<!-- Hidden unless this node is being retired. It is the one panel that answers a
     question with a consequence -- may I switch the machine off -- so it says the
     numbers rather than a colour, and it never says "done" while anything is left. -->
<section class="panel" id="drain-panel" hidden>
  <h2>Draining</h2>
  <div id="drain">&mdash;</div>
</section>

<section class="panel">
  <h2>Node</h2>
  <div class="grid" id="stats">
    <div class="stat"><div class="k">Peers connected</div><div class="v" id="peers">&mdash;</div></div>
    <div class="stat"><div class="k">Stored</div><div class="v" id="used">&mdash;</div>
      <div class="bar"><span id="bar" style="width:0"></span></div></div>
    <div class="stat"><div class="k">Your I2P address</div>
      <div class="v small" id="i2p">&mdash;</div>
      <button class="copy" type="button" id="copy">Copy</button></div>
    <div class="stat"><div class="k">Node ID</div><div class="v small" id="nodeid">&mdash;</div></div>
  </div>
</section>

<section class="panel">
  <h2>Where shards are stored</h2>
  <p class="muted">Absolute path. Pick a drive with room to spare &mdash; this is where
  encrypted shards accumulate.</p>
  <form method="post" action="/storage-dir">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input name="data_dir" id="datadir" placeholder="/media/drive/syndichan" required>
    <button type="submit">Save location</button>
  </form>
  <div class="notice">Changing this takes effect the next time the node starts, and existing
  shards are not moved for you &mdash; the store is open right now and relocating it underneath
  a running process would risk corrupting it. Copy the old folder across before restarting.</div>
</section>

<section class="panel">
  <h2>Donated disk space</h2>
  <p class="muted">The most disk this node may use. Lowering it never deletes anything on its own.</p>
  <form method="post" action="/capacity">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>Allocation <input id="capacity" type="number" name="capacity_gib"
      min="0.0625" max="8388608" step="0.25" required></label> GiB
    <button type="submit">Save allocation</button>
  </form>
</section>

{{if .Receiving}}
<section class="panel cfg">
  <h2>Receiving tips</h2>
  <p class="muted">Channels people are tipping you over. Value accumulates off chain and
    reaches your wallet when it is settled &mdash; on a schedule you choose, or when you
    close a channel.</p>
  {{range .Receiving}}
  <div class="chan">
    <h3>{{if .Peer}}{{.Peer}}{{else}}{{.ID}}{{end}}</h3>
    <table>
      <tr><td>Available</td><td class="num">{{.Mine}}</td></tr>
      <tr><td>Incoming, in flight</td><td class="num">{{.Incoming}}</td></tr>
      {{if .Outgoing}}<tr><td>Yours, at risk</td><td class="num">{{.Outgoing}}</td></tr>{{end}}
      <tr><td>Total exposure</td><td class="num">{{.Total}}</td></tr>
      <tr><td>Updates</td><td class="num">{{.Nonce}}</td></tr>
      <tr><td>Settlement</td><td>{{.Mode}} &mdash; {{.Phase}}</td></tr>
      {{if .TxHash}}<tr><td>Transaction</td><td class="mono">{{.TxHash}}</td></tr>{{end}}
      {{if .LastError}}<tr><td>Last problem</td><td class="warn">{{.LastError}}</td></tr>{{end}}
    </table>
    {{if .Locks}}
    <h4>Payments in flight</h4>
    <p class="muted">Conditional on a secret. None of this is spendable yet, and
      &ldquo;incoming&rdquo; may never arrive &mdash; which is why it is not in the
      available figure above.</p>
    <table class="locks">
      <tr><th>Payment</th><th>Direction</th><th>Amount</th><th>Expires in</th><th>Status</th></tr>
      {{range .Locks}}
      <tr>
        <td class="mono">{{.ID}}</td>
        <td>{{.Direction}}</td>
        <td class="num">{{.Amount}}</td>
        <td class="num">{{if lt .ExpiresIn 0}}expired{{else}}{{.ExpiresIn}}s{{end}}</td>
        <td>{{.Status}}</td>
      </tr>
      {{end}}
    </table>
    <p class="muted">The node settles and refunds these itself. There is nothing
      to do here.</p>
    {{end}}

    {{if .Conflicted}}
    <p class="warn">This channel is stopped: two different states were signed at one
      update number. It needs closing on chain with the best state held. No further
      tips will be accepted on it.</p>
    {{else}}
    <form method="post" action="/receiving/policy">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="channel" value="{{.ID}}">
      <label>Settle
        <select name="mode">
          <option value="on_close"{{if eq .Mode "on_close"}} selected{{end}}>only when I close</option>
          <option value="interval"{{if eq .Mode "interval"}} selected{{end}}>on a schedule</option>
        </select>
      </label>
      <label>every <input name="interval_seconds" type="number" min="60" step="60"
        value="3600" style="width:7em"></label> seconds
      <button type="submit">Save</button>
    </form>
    <form method="post" action="/receiving/settle" class="inline">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="channel" value="{{.ID}}">
      <button type="submit">Settle now</button>
    </form>
    <form method="post" action="/receiving/close" class="inline">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="channel" value="{{.ID}}">
      <button type="submit">Close channel</button>
    </form>
    {{end}}
  </div>
  {{else}}
  <p class="muted">No channels yet. One appears here when somebody opens a tipping
    channel with this node.</p>
  {{end}}
</section>
{{end}}

{{/* The tips panel sits OUTSIDE the "has channels" guard on purpose: a tip can
      be waiting at a volunteer before this node has ever tracked a channel with
      that person, and hiding the panel until a channel exists would hide the
      very first tip somebody ever received. */}}
{{if .TipsOn}}
<section id="tips">
  <h2>Tips waiting for you</h2>

  {{if .TipOutcome}}
  <p class="{{if eq .TipOutcome "accepted"}}ok{{else if eq .TipOutcome "published"}}ok{{else}}warn{{end}}" id="tip-outcome" data-outcome="{{.TipOutcome}}">
    {{if eq .TipOutcome "accepted"}}
      Tip accepted. Your node checked it and countersigned, and it is part of your
      pool now. Publish it so the person who sent it can see that you did.
    {{else if eq .TipOutcome "published"}}
      Published. The person who tipped you can now see the countersigned state.
    {{else if eq .TipOutcome "accepted_unpublished"}}
      <b>The tip is accepted</b> &mdash; that part is done and does not need doing
      again. It could not be cached at your mailbox yet, which only affects
      whether the sender can see it. Try publishing again later.
    {{else if eq .TipOutcome "conflict"}}
      Two different tips arrived for the same update number. Nothing was accepted:
      this needs looking at before any of it can be taken.
    {{else if eq .TipOutcome "superseded"}}
      That tip is already included. Your node holds a newer state for this
      channel, which counts it &mdash; nothing was lost and there is nothing to do.
    {{else if eq .TipOutcome "refused"}}
      Your node declined that tip. Nothing was accepted and nothing was lost.
    {{else if eq .TipOutcome "unreachable"}}
      That could not be completed. Nothing was accepted, and nothing is lost.
    {{else}}
      {{.TipOutcome}}
    {{end}}
    {{if .TipDetail}}<br><span class="muted mono">{{.TipDetail}}</span>{{end}}
  </p>
  {{end}}

  {{if .TipsError}}
  <p class="warn" id="tips-error">Your tips could not be checked, so this is not a
    list of what is waiting &mdash; it is not the same as having none, and nothing
    has been lost.<br><span class="muted mono">{{.TipsError}}</span></p>
  {{else if .Tips}}
  <p class="muted">Somebody has signed a tip to you and a volunteer is holding it.
    <b>No funds have been accepted yet.</b> Nothing moves until you accept it below,
    and accepting does not send a transaction or cost gas.</p>
  {{range .Tips}}
  <div class="channel tip" data-channel="{{.Channel}}" data-nonce="{{.Nonce}}" data-state="{{.State}}">
    <h3>{{if eq .State "accepted"}}Tip accepted{{else}}Tip waiting for acceptance{{end}}</h3>
    <p class="num tip-amount">{{.Amount}} ANON</p>
    <details>
      <summary>Review this tip</summary>
      <table class="locks">
        <tr><th>Channel</th><td class="mono">{{.Channel}}</td></tr>
        <tr><th>Update number</th><td class="num">{{.Nonce}}</td></tr>
        <tr><th>Amount</th><td class="num">{{.Amount}} ANON</td></tr>
        <tr><th>From</th><td class="mono">{{if .From}}{{.From}}{{else}}&mdash;{{end}}</td></tr>
        <tr><th>Status</th><td>{{if eq .State "accepted"}}accepted and countersigned by your node{{else}}waiting for your acceptance{{end}}</td></tr>
      </table>
      <p class="muted">Reading this does not accept it, and does not remove it from
        your mailbox. &ldquo;From&rdquo; is read from the chain by this node, not
        from the message the volunteer handed over.</p>
    </details>
    {{if eq .State "accepted"}}
    <p class="muted">Your node has already accepted this one and it is counted in
      your pool. Your mailbox still holds the original message &mdash; that is
      normal, and it is not a second tip. Publishing again is harmless.</p>
    <form method="post" action="/tips/publish" class="inline">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="channel" value="{{.Channel}}">
      <input type="hidden" name="nonce" value="{{.Nonce}}">
      <button type="submit" class="tip-publish">Publish accepted state</button>
    </form>
    {{else}}
    <form method="post" action="/tips/accept" class="inline">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="channel" value="{{.Channel}}">
      <input type="hidden" name="nonce" value="{{.Nonce}}">
      <button type="submit" class="tip-accept">Accept tip</button>
    </form>
    <p class="muted">Your node will verify the tip and countersign the channel
      state with its own key. There is no wallet prompt and no transaction.</p>
    {{end}}
  </div>
  {{end}}
  {{else}}
  <p class="muted" id="tips-none">No tips waiting.</p>
  {{end}}
</section>
{{end}}

{{if .HasConfig}}
<section class="panel cfg">
  <h2>Getting paid</h2>
  <p class="muted">Where this node&rsquo;s CREDIT earnings are sent. Use an address you control
    &mdash; your MetaMask, for example. Until this is set the node still serves the network,
    but nothing it earns has anywhere to go.</p>
  <form method="post" action="/config/payout">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>Payout address
      <input type="text" name="payout_address" value="{{.PayoutAddress}}"
             placeholder="0x…" size="46" spellcheck="false" autocomplete="off"></label>
    <button type="submit">Save payout address</button>
  </form>
  <p class="muted">Checked when you save: a mistyped address cannot be recovered once rewards
    are committed to an epoch.</p>
</section>

<section class="panel cfg">
  <h2>Run mode</h2>
  <p class="muted">What this node runs. Everything below is configured here &mdash; there are no launch flags.</p>
  <form method="post" action="/config/mode">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>Mode
      <select name="run_mode">
        <option value="storage"{{if eq (printf "%s" .Mode) "storage"}} selected{{end}}>Storage node (full: shards, S3, I2P, dashboard)</option>
        <option value="gateway-only"{{if eq (printf "%s" .Mode) "gateway-only"}} selected{{end}}>Gateway only (no storage/S3/I2P)</option>
        <option value="probe-only"{{if eq (printf "%s" .Mode) "probe-only"}} selected{{end}}>Probe only (verification probe)</option>
      </select>
    </label>
    <button type="submit">Save run mode</button>
    <div class="eff">Takes effect the next time the node starts.</div>
  </form>
</section>

<section class="panel cfg">
  <h2>Storage &amp; S3</h2>
  <form method="post" action="/config/storage">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="row">
      <label>S3 gateway listen address
        <input name="s3_listen" value="{{.Cfg.S3Listen}}" placeholder="127.0.0.1:9000">
      </label>
      <label class="chk"><input type="checkbox" name="cache_only" value="1"{{if .Cfg.CacheOnly}} checked{{end}}> Cache-only (host no other peers' shards)</label>
    </div>
    <div class="row">
      <label class="chk"><input type="checkbox" name="draining" value="1"{{if .Cfg.Draining}} checked{{end}}> Draining &mdash; retiring this machine</label>
    </div>
    <div class="eff">Draining takes effect immediately, not at the next start. The node stops
      accepting new shards, tells the network it is leaving, and the owners of everything it
      already holds move those shards elsewhere. Leave it running and connected until the
      panel above says it holds nothing &mdash; the shards can only leave while it is up.</div>
    <div class="row">
      <label>TLS certificate (for a non-loopback S3 listen)
        <input name="tls_cert" value="{{.Cfg.TLSCert}}" placeholder="/path/fullchain.pem">
      </label>
      <label>TLS private key
        <input name="tls_key" value="{{.Cfg.TLSKey}}" placeholder="/path/privkey.pem">
      </label>
    </div>
    <button type="submit">Save storage settings</button>
    <div class="eff">A non-loopback S3 listen requires both TLS fields. Effective next start.</div>
  </form>
</section>

<section class="panel cfg">
  <h2>Volunteer gateway</h2>
  <form method="post" action="/config/gateway">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="row">
      <label class="chk"><input type="checkbox" name="gateway_enabled" value="1"{{if .Cfg.Gateway.Enabled}} checked{{end}}> Run the volunteer gateway</label>
      <label class="chk"><input type="checkbox" name="gateway_probe" value="1"{{if .Cfg.Gateway.ProbeEnabled}} checked{{end}}> Also run the verification probe</label>
    </div>
    <div class="row">
      <label>Listen address <input name="gateway_listen" value="{{.Cfg.Gateway.ListenAddress}}" placeholder="0.0.0.0"></label>
      <label>Listen port <input name="gateway_port" type="number" min="1" max="65535" value="{{.Cfg.Gateway.ListenPort}}"></label>
    </div>
    <div class="row">
      <label>Public hostname <input name="gateway_hostname" value="{{.Cfg.Gateway.PublicHostname}}" placeholder="assigned by the controller for ACME"></label>
      <label>TLS mode
        <select name="gateway_tls_mode">
          <option value="existing"{{if eq .Cfg.Gateway.TLS.Mode "existing"}} selected{{end}}>existing (you provide the cert)</option>
          <option value="acme"{{if eq .Cfg.Gateway.TLS.Mode "acme"}} selected{{end}}>acme (controller-assigned hostname)</option>
          <option value="reverse_proxy"{{if eq .Cfg.Gateway.TLS.Mode "reverse_proxy"}} selected{{end}}>reverse_proxy</option>
        </select>
      </label>
    </div>
    <label>Registration API <input name="gateway_registration" value="{{.Cfg.Gateway.RegistrationAPI}}"></label>
    <button type="submit">Save gateway settings</button>
    <div class="eff">Effective next start.</div>
  </form>
</section>

<section class="panel cfg">
  <h2>The compute network you joined</h2>
  <p class="muted">Learned from the signed bootstrap document, not from a configured
     address. Counts only &mdash; your node knows who the peers are and does not
     publish that list to anyone who opens this page.</p>
  <div class="row" id="nw-counts"><span class="muted">loading&hellip;</span></div>
  <p class="nw__note muted" id="nw-note"></p>
</section>

<section class="panel cfg">
  <h2>What this is costing you</h2>
  <p class="muted">Live, from your own machine. The <b>grey</b> line is everything
     running &mdash; yours and the network's. The <b>coloured</b> line is what this node
     is doing. If the coloured line is flat while the grey one is high, that is your
     work, not ours.</p>
  <div class="lm-wrap">
    <canvas id="lm-canvas" height="120"></canvas>
    <div class="lm-legend">
      <span><i class="lm-sw lm-total"></i>machine load</span>
      <span><i class="lm-sw lm-node"></i>node jobs</span>
      <span><i class="lm-sw lm-gpu"></i>GPU</span>
      <span id="lm-state" class="lm-state"></span>
    </div>
  </div>
</section>

<section class="panel cfg">
  <h2>Route payments for the network</h2>
  <p class="muted">Forward other people's payments and earn a fee. This one is different
     from the others: storage lends disk you were not using, but routing lends
     <strong>liquidity</strong> &mdash; money locked in channels that you cannot spend
     elsewhere while it is committed. The limits below are how you bound that
     precisely instead of agreeing to something open-ended.</p>
  <form method="post" action="/config/router">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="row">
      <label class="chk"><input type="checkbox" name="router_enabled" value="1"{{if .Cfg.Router.Enabled}} checked{{end}}> Route payments</label>
      <label class="chk"><input type="checkbox" name="router_private_only" value="1"{{if .Cfg.Router.PrivateRoutingOnly}} checked{{end}}> Only forward privately-routed payments</label>
      <label class="chk"><input type="checkbox" name="router_watchtower" value="1"{{if .Cfg.Router.WatchtowerEnabled}} checked{{end}}> Act as a watchtower for others</label>
    </div>
    <div class="row">
      <label>Operator name <input name="router_operator" value="{{.Cfg.Router.Operator}}" placeholder="who runs this node"></label>
      <label>Fault domain <input name="router_fault_domain" value="{{.Cfg.Router.FaultDomain}}" placeholder="host, ASN or region"></label>
    </div>
    <p class="nw__note muted">A private route must cross three <em>different</em> operators.
       Leave the operator name blank and this node cannot be counted toward that &mdash; it
       would be passed over and never told why.</p>
    <div class="row">
      <label>Total liquidity ceiling <input name="router_total_max" type="number" min="0" value="{{.Cfg.Router.TotalCommittedMax}}"></label>
      <label>Max channels <input name="router_max_channels" type="number" min="0" value="{{.Cfg.Router.MaxChannels}}"></label>
    </div>
    <div class="row">
      <label>Min channel size <input name="router_min_channel" type="number" min="0" value="{{.Cfg.Router.MinChannelCapacity}}"></label>
      <label>Max channel size <input name="router_max_channel" type="number" min="0" value="{{.Cfg.Router.MaxChannelCapacity}}"></label>
    </div>
    <div class="row">
      <label>Base fee per payment <input name="router_base_fee" type="number" min="0" value="{{.Cfg.Router.BaseFeeMilli}}"></label>
      <label>Proportional fee (ppm) <input name="router_prop_fee" type="number" min="0" value="{{.Cfg.Router.ProportionalFeePPM}}"></label>
    </div>
    <div class="row">
      <label>Max payments in flight <input name="router_max_inflight" type="number" min="1" value="{{.Cfg.Router.MaxInFlight}}"></label>
      <label>Max single payment <input name="router_max_htlc" type="number" min="0" value="{{.Cfg.Router.MaxHTLCValue}}"></label>
      <label>Min timelock (blocks) <input name="router_min_timelock" type="number" min="0" value="{{.Cfg.Router.MinTimelockBlocks}}"></label>
    </div>
    <p class="nw__note muted">&ldquo;Max payments in flight&rdquo; is the jamming defence:
       without a cap, a peer can open many small locks it never settles and your liquidity
       is stuck until they expire. The timelock margin is the setting that actually loses
       money if set too low &mdash; it is the room you have to claim upstream after paying
       downstream.</p>
    <button type="submit">Save</button>
  </form>
</section>

<section class="panel cfg">
  <h2>Lend spare CPU and GPU</h2>
  <p class="muted">Run compute work units for the network on hardware you are not using.
     These are separate switches: lending cores and lending your graphics card are
     different offers, and turning compute on does not by itself lend either.</p>
  <form method="post" action="/config/compute">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="row">
      <label class="chk"><input type="checkbox" name="compute_enabled" value="1"{{if .Cfg.Compute.Enabled}} checked{{end}}> Enable compute</label>
      <label class="chk"><input type="checkbox" name="offer_cpu" value="1"{{if .Cfg.Compute.OfferCPU}} checked{{end}}> Lend spare CPU cores</label>
      <label class="chk"><input type="checkbox" name="offer_gpu" value="1"{{if .Cfg.Compute.OfferGPU}} checked{{end}}> Lend the GPU</label>
    </div>
    <div class="row">
      <label class="chk"><input type="checkbox" name="compute_idle_only" value="1"{{if .Cfg.Compute.IdleOnly}} checked{{end}}> Only when the machine is idle</label>
      <label>Cores to keep for yourself <input name="compute_reserve_cores" type="number" min="0" value="{{.Cfg.Compute.ReserveCores}}"></label>
      <label>Never use more than (0 = no limit) <input name="compute_max_cores" type="number" min="0" value="{{.Cfg.Compute.MaxCores}}"></label>
    </div>
    <div class="row">
      <label>Stop above this temperature (&deg;C, 0 = ignore) <input name="compute_max_temp" type="number" min="0" value="{{.Cfg.Compute.MaxTempC}}"></label>
      <label>Only during these hours (blank = any) <input name="compute_hours" value="{{.Cfg.Compute.Hours}}" placeholder="01:00-07:00"></label>
    </div>
    <p class="muted">Work runs from a signed catalogue with no network access. Your node
       pauses on its own when you need the machine back &mdash; pausing is not a
       withdrawal, and the network does not treat it as one.</p>
    <div class="row">
      <label>Guest kernel (vmlinux) <input name="compute_vm_kernel" value="{{.Cfg.Compute.MicroVMKernel}}" placeholder="/srv/vmlinux"></label>
      <label>Guest root filesystem <input name="compute_vm_rootfs" value="{{.Cfg.Compute.MicroVMRootFS}}" placeholder="/srv/rootfs.squashfs"></label>
    </div>
    <p class="muted"><strong>Set both to run other people&rsquo;s programs.</strong>
       Without them your node runs signed catalogue images only. Arbitrary code is
       permitted only inside a virtual machine &mdash; a container is not a strong
       enough boundary for code somebody else wrote &mdash; so this needs KVM and a
       guest image you supply. It is deliberately not downloaded for you: a node
       that fetched and booted a kernel somebody else chose would have handed over
       the machine in the act of protecting it.</p>
    <button type="submit">Save</button>
  </form>
</section>

<section class="panel cfg">
  <h2>Docker facilitation (DCS)</h2>
  <p class="muted">Run deployable containers for the network, and/or bridge a website's deploys through this node.</p>
  <form method="post" action="/config/dcs">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="row">
      <label class="chk"><input type="checkbox" name="dcs_enabled" value="1"{{if .Cfg.DCS.Enabled}} checked{{end}}> Enable DCS</label>
      <label class="chk"><input type="checkbox" name="dcs_worker" value="1"{{if .Cfg.DCS.Role.Worker}} checked{{end}}> Run containers (worker)</label>
      <label class="chk"><input type="checkbox" name="dcs_lab" value="1"{{if .Cfg.DCS.Role.Lab}} checked{{end}}> Accept vulnerable labs</label>
    </div>
    <div class="row">
      <label>Max simultaneous containers <input name="dcs_max_containers" type="number" min="0" value="{{.Cfg.DCS.Limits.MaxContainers}}"></label>
      <label>RAM ceiling (GiB) <input name="dcs_ram_gib" value="{{.RAMGiB}}"></label>
      <label>Auto spin-down (seconds, 0 = 24h) <input name="dcs_max_runtime" type="number" min="0" value="{{.Cfg.DCS.Limits.MaxRuntimeSeconds}}"></label>
    </div>
    <div class="row">
      <label>Docker endpoint <input name="dcs_docker_endpoint" value="{{.Cfg.DCS.DockerEndpoint}}" placeholder="unix:///var/run/docker.sock"></label>
      <label>Website bridge API listen (loopback only; blank = off) <input name="dcs_api_listen" value="{{.Cfg.DCS.APIListen}}" placeholder="127.0.0.1:8760"></label>
    </div>
    <label>Trusted broker node IDs (one per line &mdash; sites that may deploy on their users' behalf)
      <textarea name="dcs_trusted_brokers" placeholder="12D3KooW...">{{.Brokers}}</textarea>
    </label>
    <button type="submit">Save Docker settings</button>
    <div class="eff">Effective next start.</div>
  </form>
</section>
{{end}}

<details class="panel" id="shards-panel" open>
  <summary class="panel-summary"><h2>Stored shards</h2></summary>
  <div id="items" class="muted" style="margin-top:12px">Loading&hellip;</div>
</details>
</main>
<script>
const csrf={{printf "%q" .CSRF}};
function bytes(n){if(!n)return "0 B";const u=["B","KiB","MiB","GiB","TiB"];let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+" "+u[i]}
function esc(v){const d=document.createElement("div");d.textContent=String(v);return d.innerHTML}
function el(id){return document.getElementById(id)}

function render(s,data){
  const on=(s.peers||0)>0;
  el("peers").innerHTML='<span class="dot '+(on?"on":"off")+'"></span>'+(s.peers||0);
  el("used").textContent=bytes(s.used_bytes)+" / "+bytes(s.capacity_bytes);
  el("bar").style.width=(s.capacity_bytes?Math.min(100,s.used_bytes/s.capacity_bytes*100):0)+"%";
  el("i2p").textContent=s.i2p_address||"not published yet";
  el("nodeid").textContent=s.node_id||"";
  if(s.data_dir&&!el("datadir").value)el("datadir").value=s.data_dir;
  el("capacity").value=(s.capacity_bytes/1073741824).toFixed(2).replace(/\.?0+$/,"");
  const panel=el("drain-panel");
  if(panel){
    panel.hidden=!s.draining;
    if(s.draining){
      // Three separate sentences because they are three separate facts, and
      // collapsing them into one verdict is how "drained" gets said over shards
      // that are still on the disk.
      let out="";
      if(s.drain_held_unknown){
        out="<p class=danger>This node cannot count what it holds for other peers. "+
          "Do <b>not</b> switch it off until this reads a number.</p>";
      }else if(s.drain_shards_held>0){
        out="<p>Still holding <b>"+s.drain_shards_held+"</b> shard(s) ("+
          bytes(s.drain_bytes_held)+") for other peers. Their owners move them off, "+
          "so leave this node running and connected.</p>";
      }else{
        out="<p>No shards held for other peers.</p>";
      }
      if(s.drain_under_replicated>0){
        out+="<p class=danger><b>"+s.drain_under_replicated+"</b> of this node's own "+
          s.drain_objects+" object(s) are not yet recoverable without it. "+
          "Switching it off now loses them.</p>";
      }
      if(s.drain_safe_to_stop)out+="<p><b>Drained. It is safe to switch this machine off.</b></p>";
      el("drain").innerHTML=out;
    }
  }
  const items=data.items||[];
  el("items").innerHTML=items.length?
    "<table><thead><tr><th>Shard</th><th>Type</th><th>Size</th><th></th></tr></thead><tbody>"+
    items.map(i=>"<tr><td>"+esc(i.display_name)+"<br><code>"+esc(i.id)+"</code></td><td>"+
      esc(i.kind)+"</td><td>"+bytes(i.size)+"</td>"+
      "<td><form method=post action=/reject onsubmit=\"return confirm('Remove and reject this item?')\">"+
      "<input type=hidden name=csrf value='"+csrf+"'>"+
      "<input type=hidden name=kind value='"+esc(i.kind)+"'>"+
      "<input type=hidden name=id value='"+esc(i.id)+"'>"+
      "<button class=danger>Reject</button></form></td></tr>").join("")+"</tbody></table>"
    :"<p class=muted>Nothing stored yet. Shards arrive once a peer connects.</p>";
}
function refresh(){
  Promise.all([fetch("/api/status").then(r=>r.json()),fetch("/api/items").then(r=>r.json())])
    .then(([s,d])=>render(s,d))
    .catch(()=>{el("peers").textContent="?";el("items").textContent="Status unavailable."});
}
el("copy").addEventListener("click",()=>{
  const v=el("i2p").textContent;
  if(v&&navigator.clipboard)navigator.clipboard.writeText(v).then(()=>{
    el("copy").textContent="Copied";setTimeout(()=>el("copy").textContent="Copy",1200)})});
refresh();
// Peers and shard count move on their own; poll so the page reflects reality
// without the user reloading to find out whether anything connected.
setInterval(refresh,10000);
</script><script>
// Draws the rolling window the node keeps. Polls once a second, which matches
// the sample rate — polling faster would redraw the same data and read sensors
// for nothing.
(function () {
  var canvas = document.getElementById("lm-canvas");
  if (!canvas) { return; }
  var ctx = canvas.getContext("2d");

  function line(points, colour, scale) {
    if (!points.length) { return; }
    ctx.beginPath();
    ctx.strokeStyle = colour; ctx.lineWidth = 1.6;
    var w = canvas.width, h = canvas.height;
    points.forEach(function (v, i) {
      var x = (i / Math.max(1, points.length - 1)) * w;
      // Clamped: a load average above the scale should flatten at the top
      // rather than draw off-canvas and vanish, which reads as "no data"
      // exactly when the machine is busiest.
      var y = h - Math.min(1, Math.max(0, v / scale)) * (h - 4) - 2;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  }

  function draw(data) {
    var hist = data.history || [];
    canvas.width = canvas.clientWidth;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    line(hist.map(function (s) { return s.load_per_core; }), "#9aa4b0", 1.5);
    line(hist.map(function (s) { return s.node_jobs; }), "#f97316", Math.max(1, data.cores || 1));
    // -1 means NO READING, which is not the same as idle. Drawn as a gap so an
    // absent GPU does not appear as a permanently idle one.
    line(hist.map(function (s) { return s.gpu_busy < 0 ? 0 : s.gpu_busy; }), "#ec4899", 100);

    var state = document.getElementById("lm-state");
    var cur = data.current || {};
    if (cur.paused) {
      state.textContent = "paused \u2014 " + (cur.reason || "");
      state.style.color = "#f97316";
    } else if (cur.node_jobs > 0) {
      state.textContent = cur.node_jobs + " job(s) running";
      state.style.color = "";
    } else {
      state.textContent = "idle";
      state.style.color = "";
    }
  }

  function poll() {
    fetch("/api/load", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d) { draw(d); } })
      .catch(function () { /* a node with compute off has no meter; not an error */ });
  }
  poll();
  setInterval(poll, 1000);
})();
</script>
<script>
// Counts, refreshed slowly: the listing only changes when the bootstrap document
// does, so polling faster would ask the node the same question repeatedly.
(function () {
  var host = document.getElementById("nw-counts");
  if (!host) { return; }
  function draw(d) {
    host.innerHTML =
      "<b>" + d.total + "</b>&nbsp;compute node(s) &nbsp;&middot;&nbsp; " +
      "<b>" + d.cpu + "</b>&nbsp;CPU &nbsp;&middot;&nbsp; " +
      "<b>" + d.gpu + "</b>&nbsp;GPU &nbsp;&middot;&nbsp; " +
      "<b>" + d.microvm + "</b>&nbsp;can run arbitrary code";
    var note = document.getElementById("nw-note");
    if (d.expired) {
      // Stale is reported, not hidden: acting on an old listing dispatches to
      // peers that may be long gone.
      note.textContent = "This listing has expired \u2014 your node will not " +
        "choose peers from it until it refreshes.";
    } else if (d.total === 0) {
      note.textContent = "No compute nodes are advertising yet.";
    } else {
      note.textContent = "";
    }
  }
  function poll() {
    fetch("/api/network", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d) { draw(d); } })
      .catch(function () {});
  }
  poll();
  setInterval(poll, 30000);
})();
</script>
</body></html>`

// SetLoadMeter wires the live load graph.
//
// Called by main only when compute is enabled, so a node lending nothing shows
// no meter rather than a flat line — a graph of nothing invites the reader to
// conclude the machine is idle when in fact nothing is measuring it.
func (s *Server) SetLoadMeter(m *LoadMeter) { s.meter = m }

// SetNetworkSource wires the compute-peer summary.
func (s *Server) SetNetworkSource(f func() any) { s.network = f }

// serveNetwork reports what compute this node knows about.
//
// Counts, never the peer list. A node UI that showed every peer would publish
// the network's membership to anyone who opened it — a directory the network
// did not agree to hand out at that granularity.
func (s *Server) serveNetwork(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if s.network == nil {
		// Absent rather than zeroed: "no listing" and "a listing of nothing"
		// are different facts and a zero would read as the second.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": 0, "cpu": 0, "gpu": 0, "microvm": 0, "expired": true,
		})
		return
	}
	_ = json.NewEncoder(w).Encode(s.network())
}
