package channel

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Not part of the suite: needs the network. Run with CHAIN_PROBE=1.
func TestLiveChainReadAgainstTheDeployedContract(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	contract, err := ParseAddress("0xae70526931FF460894133201f6C8cA91bbA0E177")
	if err != nil {
		t.Fatal(err)
	}
	r := NewRPCChainReader(os.Getenv("ETH_RPC_URL"))
	_, err = r.ReadChannel(context.Background(), contract, [32]byte{0xde, 0xad, 0xbe, 0xef})

	// This address is the deployed V1 manager, whose Channel struct is nine
	// words. A V2 reader must refuse it — and must say WHY in a way that sends
	// an operator to the address rather than to their RPC.
	if !errors.Is(err, ErrNotChannelManagerV2) {
		t.Fatalf("got %v, want ErrNotChannelManagerV2", err)
	}
	t.Log("live eth_call reached the chain; the V1 address was correctly refused as not-V2")
}
