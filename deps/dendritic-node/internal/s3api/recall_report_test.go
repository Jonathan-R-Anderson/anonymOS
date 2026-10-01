package s3api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// WHAT THE SITE IS TOLD WHEN THE LEDGER CANNOT BE READ
// ====================================================
// This route is the only channel between the node and the admin purge page, so
// the distinction between "the ledger says nobody holds this" and "the ledger
// could not be read" either survives here or it does not exist. The page renders
// the first as a settled fact and the second as unknown, and rendering the
// second as the first is how an operator closes a takedown that never happened.

type fakeRecaller struct {
	record *store.RecallRecord
	err    error
}

func (f fakeRecaller) RecallForKey(context.Context, string, string, map[string]bool, string) (*store.RecallRecord, error) {
	return f.record, f.err
}

func recallServer(t *testing.T, recaller Recaller) (*httptest.Server, string, string) {
	t.Helper()
	storage, err := store.Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	const accessKey = "SYNTESTACCESS"
	const secretKey = "test-secret-key-with-at-least-32-bytes"
	api := New(storage, accessKey, secretKey, log.New(io.Discard, "", 0))
	api.SetRecaller(recaller)
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	return server, accessKey, secretKey
}

// signedPost issues a signed POST and returns the status and body WITHOUT
// failing on a non-200: the point of these tests is what the body says.
func signedPost(t *testing.T, accessKey, secretKey, url string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	const emptyPayload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	request.Header.Set("X-Amz-Content-Sha256", emptyPayload)
	signer := v4.NewSigner()
	if err := signer.SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: accessKey, SecretAccessKey: secretKey,
	}, request, emptyPayload, "s3", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("POST %s answered HTTP %d with non-JSON: %s",
			url, response.StatusCode, body)
	}
	return response.StatusCode, decoded
}

func TestAnUnreadableLedgerIsReportedAsUnknownNotAsNoHolders(t *testing.T) {
	server, accessKey, secretKey := recallServer(t, fakeRecaller{
		err: fmt.Errorf("%w (abc): unexpected end of JSON input",
			store.ErrRecallLedgerUnreadable),
	})

	_, body := signedPost(t, accessKey, secretKey,
		server.URL+"/attachments/77.png?recall")

	if body["error"] != "recall_ledger_unreadable" {
		t.Fatalf("a failed ledger read is not distinguishable by the site: %#v", body)
	}
	if _, ok := body["counts"]; ok {
		t.Fatalf("a failed ledger read answered with holder counts: %#v", body)
	}
	if note, _ := body["note"].(string); strings.Contains(note, "no confirmed remote holder") {
		t.Fatalf("a failed ledger read printed the no-holders note: %q", note)
	}
}

// A recall that failed for some OTHER reason is still reported as a failure --
// just not as a ledger that could not be read, because that one has a specific
// consequence (the holder count is unknown) the site prints differently.
func TestAnOrdinaryRecallFailureKeepsItsOwnCode(t *testing.T) {
	server, accessKey, secretKey := recallServer(t, fakeRecaller{
		err: fmt.Errorf("the coordinator refused to mint revocations"),
	})

	_, body := signedPost(t, accessKey, secretKey,
		server.URL+"/attachments/77.png?recall")

	if body["error"] != "recall_failed" {
		t.Fatalf("an ordinary failure was misclassified: %#v", body)
	}
}

// And genuine absence still reads as absence. This is the branch the site turns
// into "the placement ledger recorded no confirmed remote holder", and it has to
// keep meaning exactly that.
func TestAnObjectWithNoHoldersStillReportsCleanly(t *testing.T) {
	server, accessKey, secretKey := recallServer(t, fakeRecaller{
		record: &store.RecallRecord{ObjectID: "abc"},
	})

	status, body := signedPost(t, accessKey, secretKey,
		server.URL+"/attachments/77.png?recall")

	if status != http.StatusOK {
		t.Fatalf("an object with nothing to recall answered HTTP %d: %#v", status, body)
	}
	if _, ok := body["error"]; ok {
		t.Fatalf("an object with nothing to recall reported an error: %#v", body)
	}
	if outstanding, _ := body["outstanding"].(float64); outstanding != 0 {
		t.Fatalf("an empty record claims %v holders outstanding", outstanding)
	}
	if resolved, _ := body["resolved"].(bool); !resolved {
		t.Fatalf("an empty record is not resolved: %#v", body)
	}
}
