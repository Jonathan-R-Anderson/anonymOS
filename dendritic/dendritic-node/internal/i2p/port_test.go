package i2p

import "testing"

// TO_PORT on the accept notification is what lets one destination carry many
// ports. Parse it exactly, and reject anything that is not a plain port.
func TestParsePort(t *testing.T) {
	cases := map[string]int{
		"8080": 8080, "0": 0, "": 0, "65535": 65535,
		"65536": 0, "-1": 0, "80x": 0, "12.5": 0, "abc": 0,
	}
	for in, want := range cases {
		if got := parsePort(in); got != want {
			t.Errorf("parsePort(%q) = %d, want %d", in, got, want)
		}
	}
}

// The SAM field parser pulls TO_PORT/FROM_PORT out of an accept notification
// line, which is how a single destination reports which port was dialed.
func TestFieldExtractsPorts(t *testing.T) {
	line := "abcdefghij.b32.i2p FROM_PORT=41000 TO_PORT=443"
	if got := field(line, "TO_PORT"); got != "443" {
		t.Fatalf("TO_PORT = %q, want 443", got)
	}
	if got := parsePort(field(line, "TO_PORT")); got != 443 {
		t.Fatalf("parsed TO_PORT = %d, want 443", got)
	}
	if got := parsePort(field(line, "FROM_PORT")); got != 41000 {
		t.Fatalf("parsed FROM_PORT = %d, want 41000", got)
	}
	// A pre-3.2 router omits ports entirely -> 0, the graceful fallback.
	if got := parsePort(field("abcdefghij.b32.i2p", "TO_PORT")); got != 0 {
		t.Fatalf("missing TO_PORT should parse to 0, got %d", got)
	}
}
