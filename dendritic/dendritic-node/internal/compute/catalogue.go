package compute

// M10 slice 1 — the workload catalogue: what a node will run that is NOT a
// language runtime.
//
// WHY THIS TABLE EXISTS SEPARATELY FROM THE LANGUAGE TABLE
// --------------------------------------------------------
// The language images (python, go, c) execute a program the submitter wrote.
// They are gated on M2 for exactly that reason, and every one of them is a
// promise the node cannot keep until a microVM is under it.
//
// A catalogue workload is the opposite shape: the CODE is fixed at image-build
// time and the submitter supplies only DATA. That is what makes it deployable
// today under the catalogue rule rather than after arbitrary-code execution is
// defensible — and it is why widening this table is not, and must never become,
// a way of relaxing the arbitrary-code boundary. A workload entry names an image
// the operator's node already trusts; it never carries a program.
//
// THE CLOSED-TABLE PROPERTY
// -------------------------
// A name that is not in this map is REFUSED. It is never forwarded as an image
// string, never concatenated into a reference, never defaulted to. That single
// rule is what keeps "submitter picks the workload" from meaning "submitter
// picks the image", which is the same escape the language table is closed
// against. Everything else here is bookkeeping; that is the security property.

import (
	"errors"
	"sort"
	"strings"
)

// Workload is one entry in the catalogue: an image the node may run, plus what
// the rest of the system needs to know about it without opening the image.
type Workload struct {
	// Name is what a submitter asks for. The map key too — duplicated into the
	// value so a Workload passed around alone can still say what it is.
	Name string

	// Image is the pinned reference this workload runs. Set HERE and nowhere
	// else: the node reads it from this table after matching a name, so there is
	// no path from a request to an arbitrary image.
	Image string

	// Artifact is the published file that CONTAINS that image: a `docker save`
	// tarball, served at <base>/dl/<Artifact> exactly the way the node binary
	// is. A node that lacks the image fetches this, checks it, and loads it.
	//
	// Named here rather than derived from Image because the two are different
	// namespaces — one is a container reference, the other is a filename on a
	// web server — and deriving one from the other would mean a rename in
	// either place silently changed the other.
	Artifact string

	// Digest is the SHA-256 of that tarball, in hex, and it is the whole
	// reason a node may load an image it downloaded.
	//
	// COMPILED IN, NEVER FETCHED. This is the one field that must not travel
	// beside the bytes it describes. A digest served from the same place as the
	// artifact proves the two agree and nothing else; a digest baked into the
	// binary the operator chose to install means the site can publish new bytes
	// under this name and every node will refuse them until its operator
	// installs a build that expects them. The set of images a node will load is
	// therefore fixed at the same moment the set of workloads it will run is —
	// which is the closed-table property this file already has, extended to the
	// bytes rather than stopping at the name.
	//
	// It is the digest of the PUBLISHED TARBALL, not a claim that `docker save`
	// is reproducible from a Dockerfile. Measured: two `docker save` runs of one
	// image on Docker 29.4.2 produced identical bytes, so a rebuild from the
	// same image can be re-derived; a rebuild from the Dockerfile cannot, and
	// nothing here pretends otherwise.
	Digest string

	// Class is what this work IS — media, index, train, infer, science. It is
	// what an operator's JobClasses allowlist filters on and what the "what has
	// my machine been doing" history is written from, so it belongs to the
	// workload rather than to the request.
	Class string

	// Deterministic declares that two correct executions produce identical
	// bytes. It decides which M5 instrument applies — hash equality or
	// median-anchored tolerance — so it is a property of the image, established
	// when the image is admitted to the catalogue, never a claim by the caller.
	Deterministic bool

	// InputFile is the name the image expects its data under, relative to the
	// job's working directory ("input.jsonl"). The image does not take a path
	// argument; a submitter who could name the file could name /etc/passwd.
	InputFile string

	// OutputFile is the name the image writes its PRODUCT under, relative to
	// the same working directory ("output.jsonl"). Relative for the same reason
	// InputFile is, and declared here for a reason InputFile does not have: the
	// node is what reaches into the container and fetches it back out, and a
	// file it was never told to fetch is destroyed with the container moments
	// later.
	//
	// This field's absence was a real defect, not a missing convenience. A
	// workload with nowhere to name its output had its result collected by
	// nobody, so an embedding job returned its stdout digest, exit 0, and no
	// vectors — a silent success that the site verified by hash and paid for.
	//
	// Mirrors `output_file` in backend/services/compute_catalogue.py, which
	// already carried it; backend/tests/test_compute_catalogue.py reads both
	// tables and fails when they disagree.
	OutputFile string

	// NeedsEntrypoint is true for images that run a submitted program and false
	// for data-only workloads. Data-only is the only kind in the table today,
	// and the field exists so that stays a visible fact rather than an
	// assumption baked into the dispatcher.
	NeedsEntrypoint bool

	// DefaultDeadline is the ceiling in seconds when the caller names none. A
	// unit without a deadline can occupy a volunteer's machine forever, so every
	// workload carries a sane one rather than relying on the submitter.
	DefaultDeadline int
}

// Workloads is the catalogue. One entry: M10's first slice.
//
// Deliberately small. A workload gets in only when there is an answer to "how is
// a returned result checked" — embed has one (bit-exact hash equality over a
// deterministic vector file, see compute-images/embed/embed.py), and workloads
// whose results cannot be checked stay out however useful they would be.
var Workloads = map[string]Workload{
	"embed": {
		Name:     "embed",
		Image:    "registry.local/compute-embed:latest",
		Artifact: "compute-embed.tar",
		// Measured on 2026-08-09 from the built image, Docker 29.4.2:
		// 194,401,280 bytes, and the same digest on two consecutive saves.
		// backend/scripts/publish_compute_images.py REFUSES to publish a
		// tarball whose hash is not this one, so the artifact a node downloads
		// and the artifact this line describes cannot drift apart silently —
		// the publish fails instead of a fleet of nodes refusing.
		Digest:          "a5643d5a718f18697b3847616f122ded7bdd063d45751439a4412215d4fd65f7",
		Class:           "index",
		Deterministic:   true,
		InputFile:       "input.jsonl",
		OutputFile:      "output.jsonl",
		NeedsEntrypoint: false,
		DefaultDeadline: 600,
	},
}

// ErrUnknownWorkload is returned rather than a formatted string so a caller can
// tell "you asked for something that does not exist" from "something went
// wrong", and answer the first with a 400 and the second with a 503.
var ErrUnknownWorkload = errors.New("compute: not a catalogue workload")

// LookupWorkload resolves a submitted name.
//
// The ONLY way to get a Workload from a name. Callers must not index Workloads
// directly, because a missing key yields a zero Workload whose Image is "" —
// which would be silently forwarded as "run the empty image" instead of being
// refused.
func LookupWorkload(name string) (Workload, bool) {
	w, ok := Workloads[strings.TrimSpace(name)]
	return w, ok
}

// CatalogueWorkloads lists every workload, in a stable order.
//
// Stable because the caller is the image loader, and a node that fetched its
// catalogue in map-iteration order would log a different sequence every start
// for no reason — which makes two runs of the same failure look like two
// different failures.
func CatalogueWorkloads() []Workload {
	names := make([]string, 0, len(Workloads))
	for name := range Workloads {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Workload, 0, len(names))
	for _, name := range names {
		out = append(out, Workloads[name])
	}
	return out
}

// Fetchable reports whether this workload's image can be obtained over the
// network, and says why not when it cannot.
//
// A workload with no Artifact or no well-formed Digest is NOT fetchable, and
// that is a refusal rather than a best effort: downloading an executable image
// with nothing to check it against is the one thing the digest exists to
// prevent. Such a workload can still run on a node whose operator built the
// image by hand — it simply cannot be distributed, which is a true statement
// about the catalogue rather than a failure of the node.
func (w Workload) Fetchable() (bool, string) {
	if strings.TrimSpace(w.Artifact) == "" {
		return false, "no published artifact"
	}
	if !isHexDigest(w.Digest) {
		return false, "no published sha256"
	}
	return true, ""
}

// isHexDigest checks the shape of a sha256, and only the shape. A digest that
// is the wrong length or carries a stray "sha256:" prefix would fail every
// comparison later, at which point the message is about downloaded bytes rather
// than about a typo in this file.
func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// IsCatalogueRuntime reports whether a string is the pinned reference of a
// registered workload.
//
// This is what lets Unit.Validate accept a tag reference without accepting
// image names in general: the only non-digest runtimes that pass are the exact
// strings in this file. "ubuntu:latest" is still refused, which is the property
// the digest rule was protecting.
func IsCatalogueRuntime(reference string) bool {
	for _, w := range Workloads {
		if w.Image != "" && w.Image == reference {
			return true
		}
	}
	return false
}

// UnitFor builds the M4 work unit for a catalogue workload.
//
// The unit is the request's canonical identity: its Digest() is what the node
// hands back as a ticket, and two submissions of the same work are therefore the
// same fact rather than two. That is the idempotence property M4 exists for, and
// it only holds if the unit is built HERE — from the table — rather than from
// anything the submitter sent.
//
// Note what is not a parameter: the image, the class and the determinism flag.
// Those come from the workload. A caller who could pass them could describe
// non-deterministic work as deterministic and have M5 verify it by hash
// equality, which would fail every honest replica.
func UnitFor(w Workload, device string, params map[string]string, seed int64, deadlineSeconds int) (Unit, error) {
	// A zero Workload means the caller skipped LookupWorkload. Refused rather
	// than run, because its Image is the empty string and "" is not a thing to
	// execute.
	if strings.TrimSpace(w.Name) == "" || strings.TrimSpace(w.Image) == "" {
		return Unit{}, ErrUnknownWorkload
	}
	if strings.TrimSpace(device) == "" {
		// The overwhelmingly common case, and the safe one: CPU work needs no
		// passthrough and no vendor driver. Defaulted rather than rejected so a
		// caller that omits the field gets the conservative device, not an error
		// about a field they did not know existed.
		device = "cpu"
	}
	if deadlineSeconds <= 0 {
		deadlineSeconds = w.DefaultDeadline
	}

	// Params are COPIED. The unit's digest is its identity, so a map the caller
	// still holds a reference to could be mutated after the digest was taken and
	// the unit would no longer be what it hashed as.
	var copied map[string]string
	if len(params) > 0 {
		copied = make(map[string]string, len(params))
		for k, v := range params {
			copied[k] = v
		}
	}

	unit := Unit{
		Runtime:         w.Image,
		Needs:           device,
		Class:           w.Class,
		Deterministic:   w.Deterministic,
		Seed:            seed,
		DeadlineSeconds: deadlineSeconds,
		Params:          copied,
	}
	if err := unit.Validate(); err != nil {
		return Unit{}, err
	}
	return unit, nil
}
