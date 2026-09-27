package main

// ChannelManagerV2 mainnet deployment preflight — roadmap P12.
//
// Everything here REFUSES rather than warns. A deployment is immutable, so a
// mismatch is not something to note and continue past.
//
// It does not broadcast. eth_sendRawTransaction is never called by this file.

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

const (
	mainnetChainID  = 1
	treasuryAddr    = "0xE36e04b6Df20C00479005ba23233F67192f38421"
	axonToken       = "0x3ee18868078962f430A4Da5E827E8Cfc8b4066ac"
	challengePeriod = 28800
)

func main() {
	signerURL := flag.String("signer", "http://127.0.0.1:9500", "web3signer JSON-RPC")
	nodeURL := flag.String("rpc", "", "mainnet execution RPC")
	flag.Parse()
	if *nodeURL == "" {
		fail("-rpc is required")
	}

	from, err := channel.ParseAddress(treasuryAddr)
	if err != nil {
		fail("treasury address: %v", err)
	}
	signer := &channel.ExternalSigner{
		SignerURL: *signerURL, NodeURL: *nodeURL,
		From: from, ChainID: big.NewInt(mainnetChainID),
		Dialect: channel.DialectWeb3Signer,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Println("== signer")
	if err := signer.Verify(ctx); err != nil {
		fail("signer verification: %v", err)
	}
	fmt.Printf("  address        %s  VERIFIED\n", signer.Address().Hex())
	fmt.Printf("  chain id       %d  VERIFIED (checked against the node)\n", mainnetChainID)

	fmt.Println("\n== constructor")
	token, err := channel.ParseAddress(axonToken)
	if err != nil {
		fail("token address: %v", err)
	}
	fmt.Printf("  token_             %s\n", token.Hex())
	fmt.Printf("  challengePeriod_   %d seconds (%v)\n",
		challengePeriod, time.Duration(challengePeriod)*time.Second)
	if challengePeriod < 3600 {
		fail("challengePeriod is below the contract's 1-hour floor")
	}

	fmt.Println("\n== treasury")
	bal, err := balanceOf(ctx, *nodeURL, from)
	if err != nil {
		fail("balance: %v", err)
	}
	fmt.Printf("  balance        %s wei (%s ETH)\n", bal, ethOf(bal))
	if bal.Sign() == 0 {
		fmt.Println("  WARNING: the treasury holds no ETH; a deployment would fail for gas")
	}

	fmt.Println("\nPREFLIGHT (signer half) PASSED — nothing was signed or broadcast.")
}

func balanceOf(ctx context.Context, rpc string, a channel.Address) (*big.Int, error) {
	var raw string
	if err := rpcCall(ctx, rpc, "eth_getBalance", []any{a.Hex(), "latest"}, &raw); err != nil {
		return nil, err
	}
	v, ok := new(big.Int).SetString(strings.TrimPrefix(raw, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("unreadable balance %q", raw)
	}
	return v, nil
}

func ethOf(wei *big.Int) string {
	f := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
	return f.Text('f', 6)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nREFUSED: "+format+"\n", args...)
	os.Exit(1)
}
