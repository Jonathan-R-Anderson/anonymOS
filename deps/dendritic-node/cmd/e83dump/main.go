// Command e83dump feeds the E8.3 corpus through internal/axon/name and writes
// what came out, so a second implementation written from §11.3 can be diffed
// against it.  It contains no naming logic of its own on purpose: every answer
// here has to come from the package under comparison.
//
//	go run ./cmd/e83dump -corpus scripts/e83/corpus.json -out scripts/e83/go.json
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

type corpusFile struct {
	Seed       int      `json:"seed"`
	RootSuffix string   `json:"root_suffix"`
	Count      int      `json:"count"`
	InputsB64  []string `json:"inputs_b64"`
}

// result is one input's outcome.  Field names match the Python side exactly.
type result struct {
	Err           string   `json:"err,omitempty"`
	Canonical     string   `json:"canonical,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	Root          string   `json:"root,omitempty"`
	Namespace     string   `json:"namespace,omitempty"`
	Registrable   string   `json:"registrable,omitempty"`
	Subordinates  []string `json:"subordinates"`
	IsRegistrable bool     `json:"is_registrable"`
	ZoneID        string   `json:"zone_id,omitempty"`
	NameHash      string   `json:"name_hash,omitempty"`
	Skeleton      string   `json:"skeleton,omitempty"`
}

// errKind maps the package's sentinels onto the corpus's vocabulary.
func errKind(err error) string {
	switch {
	case errors.Is(err, name.ErrNonASCII):
		return "non-ascii"
	case errors.Is(err, name.ErrControl):
		return "control"
	case errors.Is(err, name.ErrEmptyLabel):
		return "empty-label"
	case errors.Is(err, name.ErrCharset):
		return "charset"
	case errors.Is(err, name.ErrGrammar):
		return "grammar"
	case errors.Is(err, name.ErrNotRoot):
		return "not-root"
	case errors.Is(err, name.ErrReserved):
		return "reserved"
	case errors.Is(err, name.ErrTooLong):
		return "too-long"
	case errors.Is(err, name.ErrTooManyLabels):
		return "too-many-labels"
	default:
		return "UNKNOWN:" + err.Error()
	}
}

func main() {
	corpusPath := flag.String("corpus", "scripts/e83/corpus.json", "corpus JSON")
	outPath := flag.String("out", "scripts/e83/go.json", "output JSON")
	flag.Parse()

	raw, err := os.ReadFile(*corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e83dump:", err)
		os.Exit(1)
	}
	var corpus corpusFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		fmt.Fprintln(os.Stderr, "e83dump:", err)
		os.Exit(1)
	}
	if corpus.RootSuffix != name.RootSuffix {
		fmt.Fprintf(os.Stderr, "e83dump: corpus root %q != package root %q\n",
			corpus.RootSuffix, name.RootSuffix)
		os.Exit(1)
	}

	results := make([]result, 0, len(corpus.InputsB64))
	for i, enc := range corpus.InputsB64 {
		in, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "e83dump: input %d: %v\n", i, err)
			os.Exit(1)
		}
		n, nerr := name.Normalise(string(in))
		if nerr != nil {
			results = append(results, result{Err: errKind(nerr), Subordinates: []string{}})
			continue
		}
		zone := n.ZoneID()
		r := result{
			Canonical:     n.String(),
			Labels:        n.Labels(),
			Root:          n.Root(),
			Namespace:     n.Namespace(),
			Registrable:   n.Registrable(),
			Subordinates:  n.Subordinates(),
			IsRegistrable: n.IsRegistrable(),
			ZoneID:        hex.EncodeToString(zone[:]),
			Skeleton:      name.Skeleton(n.Registrable()),
		}
		if r.Subordinates == nil {
			r.Subordinates = []string{}
		}
		if nh, err := n.NameHash(); err == nil {
			r.NameHash = hex.EncodeToString(nh[:])
		}
		results = append(results, r)
	}

	out, err := json.Marshal(map[string]any{
		"impl":        "go internal/axon/name",
		"root_suffix": name.RootSuffix,
		"results":     results,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "e83dump:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, append(out, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "e83dump:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s: %d results\n", *outPath, len(results))
}
