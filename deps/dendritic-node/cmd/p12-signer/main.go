package main

// Treasury signer provisioning — roadmap P12 deployment.
//
// THE KEY IS NEVER PRINTED, LOGGED, OR RETURNED.
//
// It is read from the environment, used to derive a public address, and
// compared against the address the operator stated. Nothing about the secret
// leaves this process: the only output is a yes/no and the public address.
//
// Reading it from the environment rather than a flag is deliberate — a flag
// would put the key in the process table, where every other user on the machine
// can read it.

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

const treasury = "0xE36e04b6Df20C00479005ba23233F67192f38421"

func main() {
	raw := strings.TrimSpace(os.Getenv("TREASURY_DELIVERY_KEY"))
	if raw == "" {
		fmt.Fprintln(os.Stderr, "TREASURY_DELIVERY_KEY is not set in the environment")
		os.Exit(1)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	// The error is reported WITHOUT the value: a malformed key must not be
	// echoed back in a diagnostic.
	if err != nil {
		fmt.Fprintln(os.Stderr, "the treasury key is not valid hex")
		os.Exit(1)
	}
	if len(b) != 32 {
		fmt.Fprintf(os.Stderr, "the treasury key is %d bytes, expected 32\n", len(b))
		os.Exit(1)
	}
	key := secp256k1.PrivKeyFromBytes(b)
	addr := channel.PubkeyAddress(key.PubKey())

	// Zero the copy we made. Go will not do this, and the process may live long
	// enough to be dumped.
	for i := range b {
		b[i] = 0
	}

	fmt.Printf("derived address : %s\n", addr.Hex())
	fmt.Printf("expected        : %s\n", strings.ToLower(treasury))
	if !strings.EqualFold(addr.Hex(), treasury) {
		fmt.Println("MISMATCH — this key does not control the treasury address")
		os.Exit(1)
	}
	fmt.Println("MATCH — the key controls the treasury address")
}
