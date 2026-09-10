package s3api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

const publicReadPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":"*","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::public/*"}]}`

// THE AUTH TRAP THIS GUARDS. ServeHTTP skips SigV4 entirely for GET/HEAD of an
// object in a public-read bucket, and it never looks at the query string. So a
// ?placement subresource hung off an object route would have been readable with
// NO CREDENTIAL AT ALL on arcade, static and releases -- handing any passer-by
// the peer id of every holder of every shard -- and ?recall would have let them
// order those shards destroyed.
func TestPlacementAndRecallAreNeverPubliclyReadable(t *testing.T) {
	storage, err := store.Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	const accessKey = "SYNTESTACCESS"
	const secretKey = "test-secret-key-with-at-least-32-bytes"
	server := httptest.NewServer(New(storage, accessKey, secretKey, log.New(io.Discard, "", 0)))
	defer server.Close()

	client := awss3.New(awss3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	})
	ctx := context.Background()
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String("public"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutBucketPolicy(ctx, &awss3.PutBucketPolicyInput{
		Bucket: aws.String("public"), Policy: aws.String(publicReadPolicy),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("public"), Key: aws.String("open.txt"),
		Body: bytes.NewReader(bytes.Repeat([]byte("open bytes\n"), 200)),
	}); err != nil {
		t.Fatal(err)
	}

	// The bypass is real: the bytes themselves come back unsigned.
	open, err := http.Get(server.URL + "/public/open.txt")
	if err != nil {
		t.Fatal(err)
	}
	open.Body.Close()
	if open.StatusCode != http.StatusOK {
		t.Fatalf("public-read object is not public: HTTP %d", open.StatusCode)
	}

	// The ledger is not.
	for _, probe := range []struct {
		method string
		url    string
	}{
		{http.MethodGet, server.URL + "/public/open.txt?placement"},
		{http.MethodGet, server.URL + "/public/open.txt?recall"},
		{http.MethodPost, server.URL + "/public/open.txt?recall"},
		{http.MethodGet, server.URL + "/public?placement"},
		{http.MethodGet, server.URL + "/?placement"},
	} {
		request, err := http.NewRequest(probe.method, probe.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s answered HTTP %d unsigned; the ledger must always "+
				"require a signature", probe.method, probe.url, response.StatusCode)
		}
	}

	// Signed, the same routes answer with observed ledger data.
	signed := signedGet(t, accessKey, secretKey, server.URL+"/public/open.txt?placement")
	var view store.PlacementView
	if err := json.Unmarshal(signed, &view); err != nil {
		t.Fatalf("placement response is not JSON: %v (%s)", err, signed)
	}
	if view.ShardCount == 0 || view.Chunks == 0 {
		t.Fatalf("placement reported no shards for a stored object: %#v", view)
	}
	if !view.ObjectPresent || view.PlainSize == 0 {
		t.Fatalf("placement did not join the manifest: %#v", view)
	}

	listing := signedGet(t, accessKey, secretKey, server.URL+"/public?placement")
	var page store.PlacementListing
	if err := json.Unmarshal(listing, &page); err != nil {
		t.Fatalf("listing response is not JSON: %v (%s)", err, listing)
	}
	if len(page.Objects) != 1 || page.Objects[0].ObjectID != view.ObjectID {
		t.Fatalf("listing did not return the stored object: %#v", page)
	}
}

// signedGet issues a SigV4-signed GET by hand: there is no SDK operation for a
// custom query subresource, and the point of the test is that the gateway
// demands a signature for one.
func signedGet(t *testing.T, accessKey, secretKey, url string) []byte {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	// sha256 of the empty body.
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
	if response.StatusCode != http.StatusOK {
		t.Fatalf("signed %s answered HTTP %d: %s", url, response.StatusCode, body)
	}
	return body
}
