// Command wallpaper-gen renders the dendritic network's radial keyspace
// topology to a desktop wallpaper PNG.
//
// This is the same graph the dendritic website embedded (backend/templates/
// includes/peer-canvas.html): peers placed on a ring by sha256(node id) folded
// into [0,1) — the same placement the DHT uses, so ring neighbours are keyspace
// neighbours — with links derived from keyspace (Kademlia finger) adjacency and
// each node coloured by its role. The website drew it live on a <canvas>; here
// we render a still, faithful to that component's palette, layout and glow, for
// use as the anonymOS desktop background.
//
// Peer data is synthesised deterministically (fixed seed) so the build is
// reproducible: no network, no live API. When the retained dendritic node
// (syndichan-node) later exposes its own peer view, this generator can be
// pointed at that instead of the synthetic set — the drawing code does not care
// where the peers come from.
//
// Pure Go stdlib, no external modules: crypto/sha256, image, image/png, math.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/png"
	"math"
	"os"
	"sort"
)

// ---- palette (verbatim from peer-canvas.html's fixed instrument palette) ----
// The website deliberately fixes these rather than inheriting a theme, because
// a topology drawn in a light theme's link colour is unreadable. We keep the
// same choice: the wallpaper is a dark instrument panel.
var (
	colBg   = rgb(0x0d1117) // stage background
	colLine = rgb(0x1e2836) // guide ring + unlit chords
	colDim  = rgb(0x7c8899) // caption ink
)

// Role colours, keyed as in the website. Order matters for multi-role blend.
var roleColor = map[string]RGB{
	"gateway":   rgb(0x3fc98a),
	"worker":    rgb(0xc98cf0),
	"payment":   rgb(0xe0b341),
	"monitor":   rgb(0x46c7d0),
	"compute":   rgb(0xf0834f),
	"microvm":   rgb(0x8f9ff5),
	"probe":     rgb(0x6fd3a8),
	"validator": rgb(0xd9d36b),
	"mailbox":   rgb(0xe08fc0),
	"delegate":  rgb(0xb06fe0),
	"storage":   rgb(0x4f9cf0),
	"drain":     rgb(0xe0685f),
}

// ROLE_ORDER, verbatim from the website: the order a multi-role node's colours
// are swept through, so a dot's colour is stable between redraws.
var roleOrder = []string{
	"gateway", "worker", "payment", "monitor",
	"compute", "microvm", "probe", "validator",
	"mailbox", "delegate", "storage",
}

// ---- RGB helpers -----------------------------------------------------------

type RGB struct{ R, G, B float64 } // components in [0,1], linear-ish sRGB values

func rgb(hex uint32) RGB {
	return RGB{
		R: float64((hex>>16)&0xff) / 255,
		G: float64((hex>>8)&0xff) / 255,
		B: float64(hex&0xff) / 255,
	}
}

func mix(a, b RGB, t float64) RGB {
	return RGB{a.R + (b.R-a.R)*t, a.G + (b.G-a.G)*t, a.B + (b.B-a.B)*t}
}

// ---- peer model ------------------------------------------------------------

type Peer struct {
	id       string
	pos      float64 // ring position in [0,1), = sha256(id) folded, as on the site
	roles    []string
	draining bool
	capBytes float64
	x, y, r  float64 // filled by layout()
}

// rolesOf mirrors the website: a draining node is drawn drain-only; otherwise
// its roles in ROLE_ORDER order, defaulting to storage.
func (p Peer) rolesOf() []string {
	if p.draining {
		return []string{"drain"}
	}
	var out []string
	for _, r := range roleOrder {
		for _, pr := range p.roles {
			if pr == r {
				out = append(out, r)
				break
			}
		}
	}
	if len(out) == 0 {
		return []string{"storage"}
	}
	return out
}

// liveColor mirrors the website's per-node colour at animation time t (ms).
// One role -> steady colour. Several -> a smooth sweep through each in turn,
// offset by ring position so the fleet does not pulse in unison. For a still we
// pick t and let each node's phase (a function of its pos) give natural variety.
func (p Peer) liveColor(t float64) RGB {
	r := p.rolesOf()
	if len(r) == 1 {
		return roleColor[r[0]]
	}
	const period = 2200.0 // ms per role
	phase := (t + p.pos*period*float64(len(r))) / period
	i := int(math.Floor(phase)) % len(r)
	frac := phase - math.Floor(phase)
	// ease so the colour dwells on each role and transitions quickly
	e := 0.0
	if frac >= 0.65 {
		e = (frac - 0.65) / 0.35
	}
	e = e * e * (3 - 2*e) // smoothstep
	return mix(roleColor[r[i]], roleColor[r[(i+1)%len(r)]], e)
}

// primaryColor is used for chords touching a node (where a gradient would not
// read) — the first role's colour, as on the site.
func (p Peer) primaryColor() RGB { return roleColor[p.rolesOf()[0]] }

// ---- deterministic synthetic fleet -----------------------------------------

// ringPos folds sha256(id) into [0,1) exactly as the website places a node:
// the top 8 bytes of the digest as a big-endian fraction of 2^64.
func ringPos(id string) float64 {
	sum := sha256.Sum256([]byte(id))
	u := binary.BigEndian.Uint64(sum[:8])
	return float64(u) / float64(1<<64)
}

// splitmix64: a tiny deterministic PRNG so role/capacity choices are stable
// across machines and runs (no math/rand global-seed dependence).
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s += 0x9E3779B97F4A7C15
	z := r.s
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}
func (r *rng) f64() float64 { return float64(r.next()>>11) / float64(1<<53) }

func synthFleet(n int) []Peer {
	rr := &rng{s: 0xDEADBEEFCAFE}
	peers := make([]Peer, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("dendritic-peer-%04d", i)
		p := Peer{id: id, pos: ringPos(id)}

		// 1–3 roles, drawn from ROLE_ORDER; storage is common, so bias toward it.
		nRoles := 1
		switch {
		case rr.f64() < 0.18:
			nRoles = 3
		case rr.f64() < 0.42:
			nRoles = 2
		}
		picked := map[string]bool{}
		for len(p.roles) < nRoles {
			role := roleOrder[rr.next()%uint64(len(roleOrder))]
			if !picked[role] {
				picked[role] = true
				p.roles = append(p.roles, role)
			}
		}
		// A few nodes are draining — the one state an operator most needs to see.
		p.draining = rr.f64() < 0.06
		// Capacity: log-uniform ~1 GB .. ~50 TB, drives dot size like the site.
		lo, hi := math.Log10(1e9), math.Log10(5e13)
		p.capBytes = math.Pow(10, lo+(hi-lo)*rr.f64())
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].pos < peers[j].pos })
	return peers
}

// synthEdges builds keyspace-adjacency links: each node links to its immediate
// ring neighbour and to Kademlia-style "fingers" at pos + 2^-k, which is what
// gives the diagram its mix of rim-hugging short links and long chords bowed
// through the centre. Deduplicated and undirected.
func synthEdges(peers []Peer) [][2]int {
	n := len(peers)
	if n < 2 {
		return nil
	}
	nearest := func(target float64) int {
		target -= math.Floor(target)
		best, bestD := 0, math.Inf(1)
		for i, p := range peers {
			d := math.Abs(p.pos - target)
			if d > 0.5 {
				d = 1 - d // wrap around the ring
			}
			if d < bestD {
				bestD, best = d, i
			}
		}
		return best
	}
	seen := map[[2]int]bool{}
	var edges [][2]int
	add := func(a, b int) {
		if a == b {
			return
		}
		if a > b {
			a, b = b, a
		}
		key := [2]int{a, b}
		if !seen[key] {
			seen[key] = true
			edges = append(edges, key)
		}
	}
	for i, p := range peers {
		add(i, (i+1)%n) // ring neighbour
		for k := 1; k <= 3; k++ {
			add(i, nearest(p.pos+1.0/math.Pow(2, float64(k))))
		}
	}
	return edges
}

// ---- canvas with additive-glow compositing ---------------------------------

type canvas struct {
	w, h int
	buf  []RGB // accumulator, cleared to bg
}

func newCanvas(w, h int) *canvas {
	c := &canvas{w: w, h: h, buf: make([]RGB, w*h)}
	for i := range c.buf {
		c.buf[i] = colBg
	}
	return c
}

func (c *canvas) add(x, y int, col RGB, a float64) {
	if x < 0 || y < 0 || x >= c.w || y >= c.h || a <= 0 {
		return
	}
	p := &c.buf[y*c.w+x]
	p.R += col.R * a
	p.G += col.G * a
	p.B += col.B * a
}

// over alpha-composites col onto the pixel (for opaque dots / lines).
func (c *canvas) over(x, y int, col RGB, a float64) {
	if x < 0 || y < 0 || x >= c.w || y >= c.h || a <= 0 {
		return
	}
	if a > 1 {
		a = 1
	}
	p := &c.buf[y*c.w+x]
	p.R = p.R*(1-a) + col.R*a
	p.G = p.G*(1-a) + col.G*a
	p.B = p.B*(1-a) + col.B*a
}

// screen blends col into the pixel like the "screen" Porter-Duff-ish operator:
// out = 1-(1-bg)*(1-col*a). Unlike linear addition it caps at 1 per channel and
// pulls toward col rather than toward white, so overlapping halos of coloured
// dots stay coloured instead of blowing out — the key to matching the website's
// look, where discrete glowing nodes sit on a dark panel.
func (c *canvas) screen(x, y int, col RGB, a float64) {
	if x < 0 || y < 0 || x >= c.w || y >= c.h || a <= 0 {
		return
	}
	if a > 1 {
		a = 1
	}
	p := &c.buf[y*c.w+x]
	p.R = 1 - (1-p.R)*(1-col.R*a)
	p.G = 1 - (1-p.G)*(1-col.G*a)
	p.B = 1 - (1-p.B)*(1-col.B*a)
}

// glow lays a soft radial falloff in col around (cx,cy) using screen blending.
// Two calls (inner bright, outer soft) approximate the website's two-pass
// shadowBlur without saturating to white where dots crowd the ring.
func (c *canvas) glow(cx, cy, sigma, amp float64, col RGB) {
	rad := int(sigma * 3.0)
	x0, x1 := int(cx)-rad, int(cx)+rad
	y0, y1 := int(cy)-rad, int(cy)+rad
	inv := 1.0 / (2 * sigma * sigma)
	for y := y0; y <= y1; y++ {
		for x := x0; x <= x1; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			d2 := dx*dx + dy*dy
			c.screen(x, y, col, amp*math.Exp(-d2*inv))
		}
	}
}

// disc draws an antialiased filled circle (opaque, alpha-composited).
func (c *canvas) disc(cx, cy, r float64, col RGB) {
	x0, x1 := int(cx-r-1), int(cx+r+1)
	y0, y1 := int(cy-r-1), int(cy+r+1)
	for y := y0; y <= y1; y++ {
		for x := x0; x <= x1; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			d := math.Sqrt(dx*dx+dy*dy) - r
			a := 0.5 - d // 1px antialiased edge
			if a > 1 {
				a = 1
			}
			c.over(x, y, col, a)
		}
	}
}

// quadChord strokes a quadratic Bézier a -> ctrl -> b (ctrl at the ring centre,
// so long keyspace jumps arc inward) with an additive tint.
func (c *canvas) quadChord(ax, ay, ctlx, ctly, bx, by float64, col RGB, width, amp float64) {
	// Arc length is bounded by the ring diameter; sample densely enough that
	// segments overlap at this width.
	steps := 220
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		mt := 1 - t
		px := mt*mt*ax + 2*mt*t*ctlx + t*t*bx
		py := mt*mt*ay + 2*mt*t*ctly + t*t*by
		c.stampSoft(px, py, width, col, amp)
	}
}

// stampSoft lays down a small soft dab of radius ~width by alpha-compositing
// (over) toward col, capped at maxA at the centre. Overlapping dabs along a
// path build an antialiased stroke that saturates to col rather than past it,
// so chords and the guide ring stay faint and even rather than streaky.
func (c *canvas) stampSoft(cx, cy, width float64, col RGB, maxA float64) {
	rad := int(width + 1)
	for y := int(cy) - rad; y <= int(cy)+rad; y++ {
		for x := int(cx) - rad; x <= int(cx)+rad; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			d := math.Sqrt(dx*dx + dy*dy)
			a := (1 - d/(width+0.5))
			if a > 0 {
				c.over(x, y, col, a*maxA)
			}
		}
	}
}

// ring strokes the antialiased guide circle.
func (c *canvas) ring(cx, cy, r, width float64, col RGB) {
	steps := int(2 * math.Pi * r)
	for i := 0; i < steps; i++ {
		a := 2 * math.Pi * float64(i) / float64(steps)
		c.stampSoft(cx+math.Cos(a)*r, cy+math.Sin(a)*r, width, col, 0.5)
	}
}

// ---- main ------------------------------------------------------------------

func main() {
	var (
		outPath = flag.String("out", "dendritic-network.png", "output PNG path")
		width   = flag.Int("w", 2560, "output width")
		height  = flag.Int("h", 1440, "output height")
		nPeers  = flag.Int("peers", 40, "number of synthetic peers")
		ss      = flag.Int("ss", 2, "supersample factor (antialiasing)")
		caption = flag.Bool("caption", true, "draw a dim wordmark + live counts")
	)
	flag.Parse()

	W, H := *width * *ss, *height * *ss
	c := newCanvas(W, H)

	cx, cy := float64(W)/2, float64(H)/2
	radius := math.Min(float64(W), float64(H)) / 2 * 0.72 // leave room for node halos

	peers := synthFleet(*nPeers)
	edges := synthEdges(peers)

	// layout(): place each peer on the ring (0.0 at 12 o'clock) and size its dot
	// by capacity, scaled from the website's ~165px stage radius to ours.
	const siteRadius = 165.0
	scale := radius / siteRadius
	for i := range peers {
		p := &peers[i]
		a := p.pos*2*math.Pi - math.Pi/2
		p.x = cx + math.Cos(a)*radius
		p.y = cy + math.Sin(a)*radius
		rSite := 3.2 + math.Min(4.4, math.Log10(1+p.capBytes/1e9)*1.5)
		p.r = rSite * scale
	}

	// Cap glow radius near the top of the faithful dot-size range, so a lone
	// huge-capacity node reads as big without bleaching its part of the ring.
	glowCap := 5.2 * scale

	// guide ring — the keyspace itself.
	c.ring(cx, cy, radius, 1.2*float64(*ss), colLine)

	// chords, bowed toward the centre.
	for _, e := range edges {
		a, b := peers[e[0]], peers[e[1]]
		c.quadChord(a.x, a.y, cx, cy, b.x, b.y, colLine, 1.0*float64(*ss), 0.42)
	}

	// nodes: glow then a crisp dot, exactly the website's order.
	for _, p := range peers {
		col := p.liveColor(0)
		// breathing glow frozen at a per-node phase so the ring reads as alive.
		breathe := 1 + 0.18*math.Sin(p.pos*4000/1400)
		// Clamp the glow radius so an outsized-capacity node (or a keyspace
		// cluster of several) does not screen-blend its neighbourhood to white.
		gr := p.r
		if gr > glowCap {
			gr = glowCap
		}
		c.glow(p.x, p.y, 0.95*gr*breathe, 0.42, col) // inner, tight
		c.glow(p.x, p.y, 1.9*gr*breathe, 0.20, col)  // outer, soft
		c.disc(p.x, p.y, p.r, col)
	}

	if *caption {
		drawCaption(c, *ss)
	}

	// Downscale (box filter) to the requested size and encode.
	img := downscale(c, *width, *height, *ss)
	f, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%dx%d, %d peers, %d links)\n", *outPath, *width, *height, len(peers), len(edges))
}

// drawCaption lays a small, dim wordmark in the lower-left, echoing the
// instrument-panel feel without cluttering the desktop. The subline stays
// descriptive rather than numeric: the node/link counts here are the synthetic
// illustration's, not a live network measurement, and printing figures on a
// wallpaper would read as live stats. Rendered with a tiny built-in 5x7 vector
// font (no font dependency).
func drawCaption(c *canvas, ss int) {
	x, y := 40*ss, c.h-70*ss
	scale := float64(3 * ss)
	drawText(c, "DENDRITIC NETWORK", float64(x), float64(y), scale, colDim, 0.9)
	// Place the subline a full glyph-height (7 rows) below the wordmark, plus a gap.
	subY := float64(y) + 7*scale + float64(9*ss)
	drawText(c, "RADIAL KEYSPACE TOPOLOGY  ANONYMOUS OVERLAY", float64(x), subY, float64(2*ss), colDim, 0.55)
}

// downscale averages ss×ss blocks into one pixel and clamps to an 8-bit image.
func downscale(c *canvas, w, h, ss int) *image.RGBA {
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	n := float64(ss * ss)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var r, g, b float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					p := c.buf[(y*ss+sy)*c.w+(x*ss+sx)]
					r += p.R
					g += p.G
					b += p.B
				}
			}
			out.Pix[out.PixOffset(x, y)+0] = clamp8(r / n)
			out.Pix[out.PixOffset(x, y)+1] = clamp8(g / n)
			out.Pix[out.PixOffset(x, y)+2] = clamp8(b / n)
			out.Pix[out.PixOffset(x, y)+3] = 255
		}
	}
	return out
}

func clamp8(v float64) uint8 {
	v *= 255
	if v < 0 {
		v = 0
	}
	if v > 255 {
		v = 255
	}
	return uint8(v + 0.5)
}
