package dcs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"sync"
	"testing"
	"time"
)

// packComposeBlob builds a reproducible tar.gz of a compose project the same way
// the site's Python packer does, so these tests exercise the real cross-language
// wire format (a compose file plus configs, no Dockerfile).
func packComposeBlob(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&raw, gzip.DefaultCompression)
	tw := tar.NewWriter(gz)
	// sorted order + fixed mtime for determinism, matching _pack_files.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	// simple insertion sort to avoid importing sort for a tiny map
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	for _, n := range names {
		data := []byte(files[n])
		_ = tw.WriteHeader(&tar.Header{
			Name: n, Size: int64(len(data)), Mode: 0o644,
			Typeflag: tar.TypeReg, ModTime: time.Unix(1_000_000_000, 0),
		})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	_ = gz.Close()
	return raw.Bytes()
}

// A compose context unpacks when a compose file is at the root, and is refused
// when only non-compose files are present. Cross-checked against the Dockerfile
// path: each rejects the other's marker.
func TestUnpackComposeContext(t *testing.T) {
	blob := packComposeBlob(t, map[string]string{
		"docker-compose.yml": "services:\n  web:\n    image: nginx\n    ports:\n      - \"80:80\"\n",
		"conf/app.conf":      "x=1\n",
	})
	files, err := UnpackComposeContext(blob)
	if err != nil {
		t.Fatalf("compose context should unpack: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("want 2 files, got %d", len(files))
	}

	// No compose file -> refused.
	noCompose := packComposeBlob(t, map[string]string{"conf/app.conf": "x=1\n"})
	if _, err := UnpackComposeContext(noCompose); err != ErrNoComposeFile {
		t.Fatalf("want ErrNoComposeFile, got %v", err)
	}

	// A Dockerfile context is not a compose context, and vice-versa.
	df, _ := PackBuildContext([]BuildFile{{Path: "Dockerfile", Mode: 0o644, Data: []byte("FROM nginx\n")}})
	if _, err := UnpackComposeContext(df); err != ErrNoComposeFile {
		t.Fatalf("Dockerfile context wrongly accepted as compose: %v", err)
	}
	if _, err := UnpackBuildContext(blob); err != ErrNoDockerfile {
		t.Fatalf("compose context wrongly accepted as Dockerfile: %v", err)
	}
}

// fakeCompose records what the agent asked docker-compose to do.
type fakeCompose struct {
	mu       sync.Mutex
	upCalls  int
	downProj []string
	primary  string
	lastEnv  []string
}

func (f *fakeCompose) Up(_ context.Context, project string, files []BuildFile, _ int, env []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upCalls++
	f.lastEnv = env
	// a plausible primary container id derived from the project
	f.primary = "cid-" + project
	return f.primary, nil
}

func (f *fakeCompose) Down(_ context.Context, project string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downProj = append(f.downProj, project)
	return nil
}

// A kind=compose deploy routes to the ComposeRunner, gets a private address for
// the primary container, and a later Destroy brings the whole project DOWN
// (not runtime.Remove, which would leak the backing services).
func TestComposeDeployRoutesToRunnerAndDestroysProject(t *testing.T) {
	worker := newIdentity(t)
	owner := newIdentity(t)
	now := time.Unix(1700000000, 0)

	blob := packComposeBlob(t, map[string]string{
		"docker-compose.yml": "services:\n  web:\n    image: vulhub/x:1\n",
	})
	blobs := newMemBlobStore()
	digest, _ := blobs.PutBlob(context.Background(), blob)

	rt := &fakeRuntime{}
	compose := &fakeCompose{}
	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()},
		rt, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = fixedClock(now)
	agent.SetBuilder(&fakeBuilder{}, blobs) // wires a.blobs (compose fetch uses it)
	agent.SetComposeRunner(compose)

	env, _ := NewEnvelope(owner, worker.ID(), MethodLaunch, DeployRequest{
		DeploymentID: "vulhub-nginx-1", Kind: "compose",
		BuildContextDigest: digest, Lab: true, PrimaryPort: 80, RuntimeSecs: 3600,
	}, now)

	reply, err := agent.HandleLaunch(context.Background(), env)
	if err != nil {
		t.Fatalf("compose deploy failed: %v", err)
	}
	if compose.upCalls != 1 {
		t.Fatalf("expected one compose up, got %d", compose.upCalls)
	}
	if len(rt.created) != 0 {
		t.Fatal("compose deploy must NOT create a single container via the runtime")
	}
	if reply.ContainerID != compose.primary || reply.Destination == "" {
		t.Fatalf("reply did not carry the primary container/destination: %+v", reply)
	}
	if !reply.Private {
		t.Fatal("a lab compose deploy must be private")
	}

	// Destroy brings the PROJECT down.
	if err := agent.Destroy(context.Background(), reply.ContainerID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if len(compose.downProj) != 1 {
		t.Fatalf("expected one compose down, got %d", len(compose.downProj))
	}
	if len(rt.removed) != 0 {
		t.Fatal("compose destroy must not call runtime.Remove")
	}
}

// A compose deploy on a worker with no ComposeRunner wired is refused clearly,
// not mis-run as a single container.
func TestComposeDeployRefusedWithoutRunner(t *testing.T) {
	worker := newIdentity(t)
	owner := newIdentity(t)
	now := time.Unix(1700000000, 0)
	blobs := newMemBlobStore()
	digest, _ := blobs.PutBlob(context.Background(),
		packComposeBlob(t, map[string]string{"docker-compose.yml": "services: {}\n"}))

	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()},
		&fakeRuntime{}, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = fixedClock(now)
	agent.SetBuilder(&fakeBuilder{}, blobs)
	// note: no SetComposeRunner

	env, _ := NewEnvelope(owner, worker.ID(), MethodLaunch, DeployRequest{
		DeploymentID: "d1", Kind: "compose", BuildContextDigest: digest, Lab: true,
	}, now)
	if _, err := agent.HandleLaunch(context.Background(), env); err == nil {
		t.Fatal("compose deploy without a runner should be refused")
	}
}
