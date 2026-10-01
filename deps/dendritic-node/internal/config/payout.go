package config

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NormalizePayoutAddress checks and lowercases an Ethereum address.
//
// Validated at the door rather than at payout time: a typo'd address is not
// recoverable once rewards are committed to an epoch's Merkle root, so this is
// one of the few settings where refusing bad input matters more than being
// lenient about it.
func NormalizePayoutAddress(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil // unset is allowed; the node just earns nothing
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "0x") {
		return "", fmt.Errorf("payout address must start with 0x")
	}
	body := lower[2:]
	if len(body) != 40 {
		return "", fmt.Errorf("payout address must be 20 bytes (42 characters including 0x)")
	}
	if _, err := hex.DecodeString(body); err != nil {
		return "", fmt.Errorf("payout address is not hexadecimal")
	}
	if body == strings.Repeat("0", 40) {
		return "", fmt.Errorf("payout address cannot be the zero address")
	}
	return lower, nil
}
