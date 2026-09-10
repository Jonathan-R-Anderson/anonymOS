package channel

// Detecting privacy leaks in anything this software emits.
//
// WHY THIS IS THE CHECK THAT MATTERS MOST
// ---------------------------------------
// Debug logging added during an incident and never removed has defeated more
// privacy systems than cryptanalysis has. The onion, the blinding and the
// commitments are all correct and all irrelevant if a router writes its hop
// instruction to a log file, or an error message helpfully includes the
// recipient it failed to reach.
//
// So this is a detector that can be pointed at logs, errors, API responses or
// telemetry, and a CI test that points it at everything this package can say.
//
// WHY IT SCANS FOR VALUES RATHER THAN PATTERNS
// --------------------------------------------
// A regex for "looks like an address" catches the obvious cases and misses the
// ones that matter: a stream id, an invoice id, a channel id are all just
// bytes. The only reliable check is to hold the ACTUAL secret values a test
// created and confirm none of them appear in the output — which is why Detector
// takes the values rather than trying to recognise them.

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Detector holds values that must never be emitted.
type Detector struct {
	// labelled by what they are, so a failure says WHICH class leaked rather
	// than just that something did.
	secrets map[string][]string
}

func NewDetector() *Detector {
	return &Detector{secrets: map[string][]string{}}
}

// Watch registers a value that must never appear in output.
//
// Registers several encodings of the same bytes, because a leak through a
// different representation is still a leak — a channel id logged as hex and a
// channel id logged raw are equally identifying.
func (d *Detector) Watch(kind string, value any) {
	var forms []string
	switch v := value.(type) {
	case string:
		if v == "" {
			return
		}
		forms = append(forms, v, hex.EncodeToString([]byte(v)))
	case []byte:
		if len(v) == 0 {
			return
		}
		forms = append(forms, string(v), hex.EncodeToString(v))
	case [32]byte:
		forms = append(forms, hex.EncodeToString(v[:]), string(v[:]))
	case NodeID:
		if v == "" {
			return
		}
		forms = append(forms, string(v), hex.EncodeToString([]byte(v)))
	case ChannelID:
		if v == "" {
			return
		}
		forms = append(forms, string(v), hex.EncodeToString([]byte(v)))
	case Amount:
		// Amounts are watched as their decimal text. Deliberately included:
		// "failed to forward 12345" names the amount as surely as a field would.
		forms = append(forms, fmt.Sprintf("%d", int64(v)))
	default:
		forms = append(forms, fmt.Sprintf("%v", v))
	}
	for _, f := range forms {
		// One- and two-character forms would match everything. A secret that
		// short is not protectable by scanning and should not be pretended to be.
		if len(f) >= 6 {
			d.secrets[kind] = append(d.secrets[kind], f)
		}
	}
}

// Leak describes one finding.
type Leak struct {
	Kind  string
	Value string
	Where string
}

func (l Leak) String() string {
	return fmt.Sprintf("%s leaked in %s: %q", l.Kind, l.Where, l.Value)
}

// Scan checks text for any watched value.
func (d *Detector) Scan(where, text string) []Leak {
	var found []Leak
	lower := strings.ToLower(text)
	for kind, values := range d.secrets {
		for _, v := range values {
			if strings.Contains(lower, strings.ToLower(v)) {
				found = append(found, Leak{Kind: kind, Value: v, Where: where})
			}
		}
	}
	return found
}

// ScanAll checks many outputs at once.
func (d *Detector) ScanAll(outputs map[string]string) []Leak {
	var all []Leak
	for where, text := range outputs {
		all = append(all, d.Scan(where, text)...)
	}
	return all
}
