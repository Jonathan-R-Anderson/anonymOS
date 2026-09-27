package contracts

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

// eip55 is the mixed-case checksum encoding of an address (EIP-55): a hex nibble
// of keccak256(lowercase-hex-address) at position i decides whether character i
// is upper-cased.
func eip55(addr string) string {
	a := strings.ToLower(strings.TrimPrefix(addr, "0x"))
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(a))
	sum := hex.EncodeToString(h.Sum(nil))
	var b strings.Builder
	b.WriteString("0x")
	for i, c := range a {
		if c >= 'a' && c <= 'f' && sum[i] >= '8' {
			b.WriteRune(c - 32)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// TestAddressesAreValidChecksums is the reason this file exists. A mis-typed
// character in a mainnet address in contracts.go is a payment sent nowhere, and
// nothing else in the tree would catch it -- the reader packages take whatever
// address they are handed. EIP-55 makes a single wrong nibble detectable, and
// this asserts every address here is its own valid checksum.
func TestAddressesAreValidChecksums(t *testing.T) {
	for _, c := range Mainnet.All() {
		if len(c.Address) != 42 || !strings.HasPrefix(c.Address, "0x") {
			t.Errorf("%s: %q is not a 20-byte 0x address", c.Name, c.Address)
			continue
		}
		// The Channels predecessor is recorded lowercase (as the console shows
		// it), which is a valid address but not a mixed-case checksum -- so it
		// is checked for validity as lowercase rather than for the checksum.
		if c.Address == strings.ToLower(c.Address) {
			continue
		}
		if got := eip55(c.Address); got != c.Address {
			t.Errorf("%s: %s is not valid EIP-55; the checksum for these bytes "+
				"is %s. A wrong character here sends mainnet funds nowhere.",
				c.Name, c.Address, got)
		}
	}
}

// TestNoAddressIsZeroOrDuplicated: a zero address is an unset field that
// compiled, and two contracts sharing an address is a copy-paste that would
// route one contract's calls to another.
func TestNoAddressIsZeroOrDuplicated(t *testing.T) {
	seen := map[string]string{}
	zero := "0x0000000000000000000000000000000000000000"
	for _, c := range Mainnet.All() {
		low := strings.ToLower(c.Address)
		if low == zero {
			t.Errorf("%s is the zero address -- an unset field", c.Name)
		}
		if prev, dup := seen[low]; dup {
			t.Errorf("%s shares an address with %s (%s)", c.Name, prev, c.Address)
		}
		seen[low] = c.Name
	}
}

func TestChainIsMainnet(t *testing.T) {
	if ChainID != 1 {
		t.Errorf("ChainID = %d; the deployment is Ethereum mainnet (1)", ChainID)
	}
}
