package aggregator

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// A receipt exactly as a node uploads it. Produced by storage-client's
// facilitation package, pasted verbatim.
//
// The two modules cannot import each other, so this fixture is the only thing
// standing between them and a wire mismatch — and a mismatch here does not
// error. Go's json decoder skips unknown keys, so the receipt would land as an
// empty struct, fail its signature check, and be dropped at settlement while
// every node reported success.
const nodeUploadedReceipt = `{"receipt":{"ProviderNodeID":[241,228,77,90,193,173,146,113,63,87,156,182,26,216,23,26,109,71,196,53,182,6,60,246,131,171,22,232,204,168,76,77],"VerifierNodeID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"ServiceType":2,"JobID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"ChallengeHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"ResultHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Epoch":7,"StartedAt":0,"CompletedAt":0,"Quantity":20480,"Quality":1,"Nonce":11},"provider_pub":"SB7edy2hV4XJ5ZoIYgG4w/nDBxKeP8bX80qk3+1YFOU=","provider_sig":"63eSwcCUzqyBZ+PHISIr97B0u4sQvFRr2+Q1ybtyhjjBJG+Dx6Oo+JCpxaaHyTSD+HGkAIps6eAdZpsIt6V2AQ==","witnesses":[{"pub":"d3tXnCdZjsvh4e/W5xdtcB7iuYyuCtqDH9jBQKmvP1Q=","sig":"tZScEZI9Cszrl4OuG482LscPyUqmcJ7YH5lMizCZJsDvtsEWFN1dCMmWNXMs6MayDag9xXsuPYbwK1e0DnGpDA=="}]}`

const nodeReceiptHash = "718355aaaf23afa8951031d831d6f3f6ccaeb4428215eca817dbfc68b26324e7"

func TestDecodesAReceiptTheNodeActuallySent(t *testing.T) {
	var sr SignedReceipt
	if err := json.Unmarshal([]byte(nodeUploadedReceipt), &sr); err != nil {
		t.Fatalf("could not decode a node upload: %v", err)
	}
	if len(sr.ProviderPub) != ed25519.PublicKeySize {
		t.Fatalf("provider key did not decode (%d bytes) — wire tags have drifted", len(sr.ProviderPub))
	}
	got := CanonicalReceiptHash(sr.Receipt)
	if hex.EncodeToString(got[:]) != nodeReceiptHash {
		t.Fatalf("recomputed hash differs from the node's\n got: %s\nwant: %s",
			hex.EncodeToString(got[:]), nodeReceiptHash)
	}
	// And the signatures must verify, which is what settlement relies on.
	if err := ValidateReceipt(sr, 1); err != nil {
		t.Fatalf("a genuine node receipt failed validation: %v", err)
	}
}
