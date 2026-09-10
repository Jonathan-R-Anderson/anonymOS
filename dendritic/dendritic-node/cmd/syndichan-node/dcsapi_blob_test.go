package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/dcs"
)

// memBlobs is the smallest BlobStore that exercises the handler. The real one
// needs a Store, a datadir and a lock; none of that is what these tests are
// about.
type memBlobs struct{ data map[string][]byte }

func (m *memBlobs) PutBlob(_ context.Context, b []byte) (string, error) {
	d := dcs.BlobDigest(b)
	if m.data == nil {
		m.data = map[string][]byte{}
	}
	m.data[d] = b
	return d, nil
}

func (m *memBlobs) GetBlob(_ context.Context, digest string) ([]byte, error) {
	b, ok := m.data[digest]
	if !ok {
		return nil, io.EOF
	}
	return b, nil
}

func newAPI(t *testing.T) (*bridgeAPI, string) {
	t.Helper()
	blobs := &memBlobs{}
	digest, err := blobs.PutBlob(context.Background(), []byte("a build context"))
	if err != nil {
		t.Fatal(err)
	}
	return &bridgeAPI{blobs: blobs, logger: log.New(io.Discard, "", 0)}, digest
}

// Without a read path a publisher can only assert it once called PUT. This is
// the check that makes reclaiming a local copy defensible.
func TestBlobGetReturnsWhatWasStored(t *testing.T) {
	api, digest := newAPI(t)
	for _, url := range []string{"/dcs/blob?digest=" + digest, "/dcs/blob/" + digest} {
		rec := httptest.NewRecorder()
		api.handleBlob(rec, httptest.NewRequest(http.MethodGet, url, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", url, rec.Code)
		}
		if got := rec.Body.String(); got != "a build context" {
			t.Fatalf("%s: got %q", url, got)
		}
	}
}

// HEAD is what makes "is it still there?" cost a lookup rather than a transfer,
// which is the whole point of using it before reclaiming space.
func TestBlobHeadHasNoBodyButReportsSize(t *testing.T) {
	api, digest := newAPI(t)
	rec := httptest.NewRecorder()
	api.handleBlob(rec, httptest.NewRequest(http.MethodHead, "/dcs/blob?digest="+digest, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD returned a body of %d bytes", rec.Body.Len())
	}
	if rec.Header().Get("Content-Length") != "15" {
		t.Fatalf("Content-Length = %q, want 15", rec.Header().Get("Content-Length"))
	}
}

func TestMissingBlobIsNotFound(t *testing.T) {
	api, _ := newAPI(t)
	rec := httptest.NewRecorder()
	api.handleBlob(rec, httptest.NewRequest(http.MethodGet, "/dcs/blob?digest=sha256:deadbeef", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

// A content-addressed store handing back bytes that do not match the requested
// digest is worse than a miss, because the caller would trust them. It must be
// distinguishable from "absent" so an operator knows the copy is corrupt.
func TestCorruptBlobIsNotServedAsIfItWereFine(t *testing.T) {
	blobs := &memBlobs{data: map[string][]byte{"sha256:notthehash": []byte("tampered")}}
	api := &bridgeAPI{blobs: blobs, logger: log.New(io.Discard, "", 0)}
	rec := httptest.NewRecorder()
	api.handleBlob(rec, httptest.NewRequest(http.MethodGet, "/dcs/blob?digest=sha256:notthehash", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 (corrupt, not merely absent)", rec.Code)
	}
	if rec.Body.String() == "tampered" {
		t.Fatal("served bytes that do not match the requested digest")
	}
}

func TestPutStillWorks(t *testing.T) {
	api, _ := newAPI(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/dcs/blob", io.NopCloser(readerOf("new ctx")))
	api.handleBlob(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT regressed: got %d", rec.Code)
	}
}

type strReader struct {
	s string
	i int
}

func readerOf(s string) io.Reader { return &strReader{s: s} }
func (r *strReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}
