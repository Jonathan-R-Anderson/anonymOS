package dcs

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The archive endpoint is the only channel by which a compute job receives its
// data and returns its result. There is no bind mount and no network, so a
// mistake here is not a degraded job — it is a job that cannot exist.
//
// These tests pin the wire format because the failures it produces are silent:
// a path sent as part of the URL rather than as a query parameter, or an id
// left unescaped, gives a 404 that looks exactly like "the job wrote nothing".

// newTestClient points a DockerClient at an httptest server instead of the
// docker socket. Same code path; the transport is the only difference.
func newTestClient(handler http.Handler) (*DockerClient, func()) {
	server := httptest.NewServer(handler)
	return &DockerClient{http: server.Client(), apiBase: server.URL}, server.Close
}

func TestPutArchiveSendsTheTarToTheRightPath(t *testing.T) {
	var (
		gotMethod, gotPath, gotQuery, gotType string
		gotBody                               []byte
	)
	client, close := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotQuery = r.URL.Query().Get("path")
		gotType = r.Header.Get("Content-Type")
		gotBody, _ = readAllBody(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer close()

	payload := []byte("a tar, more or less")
	if err := client.PutArchive(context.Background(), "abc123", "/", payload); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method %s, want PUT", gotMethod)
	}
	if gotPath != "/containers/abc123/archive" {
		t.Errorf("path %q", gotPath)
	}
	// The destination is a QUERY parameter. Appended to the URL path instead, it
	// would silently address a different container.
	if gotQuery != "/" {
		t.Errorf("path parameter %q, want /", gotQuery)
	}
	if gotType != "application/x-tar" {
		t.Errorf("content type %q", gotType)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Errorf("body %q, want %q", gotBody, payload)
	}
}

// A container id and an in-container path both reach this from a caller that is
// relaying somebody else's request, so neither may be pasted into a URL raw: a
// path of "/work/out?x=1" must not become a second query parameter.
func TestArchivePathsAreEscaped(t *testing.T) {
	var gotPath, gotQuery, gotRaw string
	client, close := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotRaw = r.URL.EscapedPath(), r.URL.Query().Get("path"), r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer close()

	if _, err := client.GetArchive(context.Background(), "id/../other", "/work/out put?x=1&y=2"); err != nil {
		t.Fatal(err)
	}
	// The id keeps its slashes ESCAPED, so a crafted id cannot walk up to a
	// different endpoint on the daemon's API.
	if gotPath != "/containers/id%2F..%2Fother/archive" {
		t.Errorf("container id was not escaped into the URL: %q", gotPath)
	}
	if gotQuery != "/work/out put?x=1&y=2" {
		t.Errorf("path parameter arrived as %q; it was not escaped", gotQuery)
	}
	if strings.Count(gotRaw, "&") != 0 && !strings.Contains(gotRaw, "%26") {
		t.Errorf("raw query %q leaked an unescaped separator", gotRaw)
	}
}

func TestGetArchiveReturnsTheTar(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	body := []byte("tar bytes")
	client, close := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotQuery = r.URL.Query().Get("path")
		_, _ = w.Write(body)
	}))
	defer close()

	got, err := client.GetArchive(context.Background(), "abc123", "/work/output.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method %s, want GET", gotMethod)
	}
	if gotPath != "/containers/abc123/archive" {
		t.Errorf("path %q", gotPath)
	}
	if gotQuery != "/work/output.jsonl" {
		t.Errorf("path parameter %q", gotQuery)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("got %q, want %q", got, body)
	}
}

// The sentinel is the whole point of the 404 case: "the job produced no output
// file" is a normal outcome that must not fail the job, while "the daemon did
// not answer" is a broken node. A caller that cannot tell them apart either
// fails honest jobs or reports a dead daemon as an empty result.
func TestMissingPathIsASentinelNotATransportFailure(t *testing.T) {
	client, close := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Could not find the file /work/output.jsonl in container abc"}`))
	}))
	defer close()

	_, err := client.GetArchive(context.Background(), "abc", "/work/output.jsonl")
	if !errors.Is(err, ErrArchiveMissing) {
		t.Fatalf("404 gave %v, want ErrArchiveMissing", err)
	}
	if !strings.Contains(err.Error(), "/work/output.jsonl") {
		t.Errorf("the error does not name the path: %v", err)
	}
	// The same on the way in: extracting into a directory that does not exist.
	if err := client.PutArchive(context.Background(), "abc", "/nope", nil); !errors.Is(err, ErrArchiveMissing) {
		t.Fatalf("a 404 on put gave %v, want ErrArchiveMissing", err)
	}
}

// Anything that is not a 404 is a real failure and must NOT wear the missing
// sentinel — a 500 reported as "no output" loses a result silently.
func TestOtherFailuresAreNotTheMissingSentinel(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusConflict, http.StatusForbidden} {
		client, close := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"container rootfs is marked read-only"}`))
		}))
		_, err := client.GetArchive(context.Background(), "abc", "/work/out")
		close()
		if err == nil {
			t.Fatalf("HTTP %d was reported as success", status)
		}
		if errors.Is(err, ErrArchiveMissing) {
			t.Fatalf("HTTP %d was reported as a missing file", status)
		}
		// The daemon's own explanation is passed through: "container rootfs is
		// marked read-only" is the failure an operator will actually hit, and it
		// is unguessable from a bare status code.
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("HTTP %d dropped the daemon's message: %v", status, err)
		}
	}
}

// The container chooses how big the file it writes is, and the node reads that
// file into memory. Without a bound, a program that writes until the disk is
// full hands the node an out-of-memory kill as its result.
func TestOversizeArchiveIsRefusedRatherThanBuffered(t *testing.T) {
	client, close := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("x"), 1<<20)
		for written := 0; written <= MaxArchiveBytes; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer close()

	_, err := client.GetArchive(context.Background(), "abc", "/work/huge")
	if !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("an oversize archive gave %v, want ErrArchiveTooLarge", err)
	}
}

// Exactly at the limit is fine; the cap refuses what is larger, not what fits.
func TestArchiveAtTheLimitIsAccepted(t *testing.T) {
	client, close := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), MaxArchiveBytes))
	}))
	defer close()

	got, err := client.GetArchive(context.Background(), "abc", "/work/exact")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxArchiveBytes {
		t.Errorf("got %d bytes, want %d", len(got), MaxArchiveBytes)
	}
}

// The hardened profile is unchanged by any of this: only a caller that says so
// gets a writable root, and that is the only field this touches.
func TestWritableRootfsIsOptInAndNothingElseChanges(t *testing.T) {
	if body := hardened(ContainerSpec{Image: "sha256:abcd"}); !body.HostConfig.ReadonlyRootfs {
		t.Fatal("the default spec produced a writable root filesystem")
	}
	body := hardened(ContainerSpec{Image: "sha256:abcd", WritableRootfs: true})
	if body.HostConfig.ReadonlyRootfs {
		t.Fatal("WritableRootfs was ignored; the archive endpoint would refuse the container")
	}
	if body.HostConfig.Privileged || body.HostConfig.NetworkMode != "none" || !body.NetworkDisabled {
		t.Fatal("a writable root loosened something else in the profile")
	}
	if len(body.HostConfig.CapDrop) != 1 || body.HostConfig.CapDrop[0] != "ALL" {
		t.Fatalf("capabilities not fully dropped: %v", body.HostConfig.CapDrop)
	}
	if body.HostConfig.PidsLimit == nil || *body.HostConfig.PidsLimit <= 0 {
		t.Fatal("no pids limit")
	}
}

func readAllBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}
