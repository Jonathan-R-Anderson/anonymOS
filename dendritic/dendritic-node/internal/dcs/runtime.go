package dcs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The Docker Engine API is spoken directly over its unix socket with net/http
// rather than through github.com/docker/docker. That client pulls in an
// enormous dependency tree for what is, here, four endpoints -- and this
// binary cross-compiles to six targets with CGO_ENABLED=0, where a smaller
// dependency surface is worth more than convenience wrappers.

type DockerClient struct {
	http     *http.Client
	long     *http.Client
	endpoint string
	apiBase  string
}

func NewDockerClient(endpoint string) (*DockerClient, error) {
	socket := strings.TrimPrefix(endpoint, "unix://")
	if socket == "" || !strings.HasPrefix(endpoint, "unix://") {
		return nil, fmt.Errorf("dcs: only unix:// docker endpoints are supported, got %q", endpoint)
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}
	return &DockerClient{
		endpoint: endpoint,
		apiBase:  "http://docker",
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{DialContext: dial},
		},
		// No client-side deadline: the CALLER's context is the deadline.
		//
		// Loading a catalogue image means handing the daemon ~190 MB and
		// waiting while it unpacks several hundred megabytes of layers, which on
		// a Raspberry Pi takes minutes. The 60-second client above would abort
		// that mid-stream every time, and the failure would arrive as a
		// transport error rather than as anything mentioning a timeout — so the
		// operator would see an image that "cannot be loaded" on exactly the
		// hardware most likely to be volunteering.
		long: &http.Client{Transport: &http.Transport{DialContext: dial}},
	}, nil
}

func (c *DockerClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dcs: docker %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&msg)
		return fmt.Errorf("dcs: docker %s %s: HTTP %d: %s",
			method, path, resp.StatusCode, msg.Message)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *DockerClient) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/_ping", nil, nil)
}

// ContainerSpec is what a deployment asks for. It is deliberately NOT the
// Docker create body: everything dangerous in that body is absent here, so a
// deployer has no field in which to request it.
type ContainerSpec struct {
	Name             string
	Image            string // digest-pinned reference
	Cmd              []string
	Env              []string
	Labels           map[string]string
	MemoryLimitBytes int64
	NanoCPUs         int64
	PidsLimit        int64
	// WritableRootfs turns the read-only root filesystem OFF for this one
	// container. The zero value is the hardened setting, so a caller that omits
	// the field gets a read-only root rather than a writable one — the mistake
	// this way round is a broken container, not a silently weakened sandbox.
	//
	// It exists for exactly one reason: the Docker daemon REFUSES
	// PUT /containers/{id}/archive on a container whose rootfs is marked
	// read-only ("container rootfs is marked read-only"), running or stopped.
	// A workload that must be HANDED a data file therefore cannot also have a
	// read-only root, and the alternative — a tmpfs at the delivery path — is
	// worse than useless: the archive endpoint writes through the image layer,
	// which the tmpfs then masks, so the files exist and the program cannot see
	// them. Both behaviours were verified against Docker 29 rather than assumed.
	//
	// Everything else in the profile still applies: no network, all capabilities
	// dropped, no-new-privileges, an unprivileged uid, a pids limit and a memory
	// limit, and the container is destroyed after one job. What is lost is the
	// disk bound: a program can now fill the container's own layer, where before
	// it could only fill a size-capped tmpfs.
	WritableRootfs bool
	TmpfsMounts    map[string]string
	// Lab marks a deliberately vulnerable workload. It tightens the profile
	// further; it never loosens it.
	Lab bool
}

// HostConfig fragments we always set, and the ones we never accept, live here
// so the profile is one auditable block rather than scattered assignments.
type dockerCreateBody struct {
	Image           string            `json:"Image"`
	Cmd             []string          `json:"Cmd,omitempty"`
	Env             []string          `json:"Env,omitempty"`
	Labels          map[string]string `json:"Labels,omitempty"`
	NetworkDisabled bool              `json:"NetworkDisabled"`
	HostConfig      dockerHostConfig  `json:"HostConfig"`
}

type dockerHostConfig struct {
	Memory         int64             `json:"Memory,omitempty"`
	NanoCpus       int64             `json:"NanoCpus,omitempty"`
	PidsLimit      *int64            `json:"PidsLimit,omitempty"`
	CapDrop        []string          `json:"CapDrop"`
	SecurityOpt    []string          `json:"SecurityOpt"`
	ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
	Tmpfs          map[string]string `json:"Tmpfs,omitempty"`
	NetworkMode    string            `json:"NetworkMode"`
	Privileged     bool              `json:"Privileged"`
	AutoRemove     bool              `json:"AutoRemove"`
	RestartPolicy  struct {
		Name string `json:"Name"`
	} `json:"RestartPolicy"`
}

// hardened builds the create body. This is the only place a container is
// configured, which is what makes the guarantees checkable: there is no second
// path where Privileged could become true.
func hardened(spec ContainerSpec) dockerCreateBody {
	pids := spec.PidsLimit
	if pids <= 0 {
		pids = 256
	}
	tmpfs := spec.TmpfsMounts
	if tmpfs == nil {
		tmpfs = map[string]string{}
	}
	// A read-only rootfs with nowhere to write breaks most images, so /tmp is
	// always provided as a small tmpfs rather than leaving the operator to
	// discover the failure.
	if _, ok := tmpfs["/tmp"]; !ok {
		tmpfs["/tmp"] = "rw,noexec,nosuid,size=64m"
	}

	body := dockerCreateBody{
		Image:  spec.Image,
		Cmd:    spec.Cmd,
		Env:    spec.Env,
		Labels: spec.Labels,
		// Docker's own networking is disabled entirely. The container reaches
		// the network only through the I2P destination the agent attaches, so
		// there is no bridge, no port binding, and no route to the host LAN.
		NetworkDisabled: true,
		HostConfig: dockerHostConfig{
			Memory:    spec.MemoryLimitBytes,
			NanoCpus:  spec.NanoCPUs,
			PidsLimit: &pids,
			CapDrop:   []string{"ALL"},
			SecurityOpt: []string{
				"no-new-privileges:true",
			},
			// Read-only unless the caller explicitly asked otherwise, so the
			// default of every present and future call site is the hard one.
			ReadonlyRootfs: !spec.WritableRootfs,
			Tmpfs:          tmpfs,
			NetworkMode:    "none",
			Privileged:     false,
		},
	}
	// A lab container never restarts: a vulnerable service that resurrects
	// itself outlives the researcher's attention, which is exactly what the
	// runtime ceiling exists to prevent.
	if spec.Lab {
		body.HostConfig.RestartPolicy.Name = "no"
		body.HostConfig.AutoRemove = false
	} else {
		body.HostConfig.RestartPolicy.Name = "no"
	}
	return body
}

var ErrEmptyImage = errors.New("dcs: container spec has no image")

// Create makes the container. It never starts it: the agent attaches the I2P
// destination between create and start, so a container cannot run for even an
// instant before its network identity exists.
func (c *DockerClient) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	if strings.TrimSpace(spec.Image) == "" {
		return "", ErrEmptyImage
	}
	body := hardened(spec)
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	path := "/containers/create"
	if spec.Name != "" {
		path += "?name=" + spec.Name
	}
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// BuildImage builds an image from a packed build context (a gzip'd tar with a
// Dockerfile at its root -- exactly what PackBuildContext produces). The build
// runs in the local Docker daemon; the resulting image is tagged and then run
// like any other. Build output is drained but not returned to the deployer,
// which would leak host paths and the daemon's environment.
func (c *DockerClient) BuildImage(ctx context.Context, contextBlob []byte, tag string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiBase+"/build?t="+tag+"&dockerfile=Dockerfile&forcerm=1&networkmode=none", bytes.NewReader(contextBlob))
	if err != nil {
		return err
	}
	// Docker auto-detects a gzip'd tar; application/x-tar is the documented type.
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dcs: docker build: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("dcs: docker build failed: HTTP %d", resp.StatusCode)
	}
	// The /build response streams newline-delimited JSON with a final error
	// object if the build failed despite a 200. Scan for it rather than trust
	// the status code alone.
	dec := json.NewDecoder(resp.Body)
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err != nil {
			break // EOF or done
		}
		if msg.Error != "" {
			return fmt.Errorf("dcs: docker build failed: %s", msg.Error)
		}
	}
	return nil
}

// ImageExists reports whether a reference resolves to an image the daemon
// already holds.
//
// The question a node asks before deciding to download 190 MB, and the question
// it asks again afterwards to confirm the load actually produced the tag it was
// promised. A 404 is a normal answer here — "no, and that is not a problem" —
// so it is returned as (false, nil); anything else is the daemon failing, which
// is a different thing and must not be reported as a missing image.
func (c *DockerClient) ImageExists(ctx context.Context, reference string) (bool, error) {
	if strings.TrimSpace(reference) == "" {
		return false, ErrEmptyImage
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.apiBase+"/images/"+url.PathEscape(reference)+"/json", nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("dcs: docker inspect image %s: %w", reference, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode >= 400:
		return false, fmt.Errorf("dcs: docker inspect image %s: HTTP %d",
			reference, resp.StatusCode)
	}
	return true, nil
}

// LoadImage installs an image from a `docker save` tarball.
//
// THE CALLER MUST HAVE VERIFIED THE BYTES FIRST. This hands a whole filesystem
// image to a root daemon, which will then run it; there is nothing this function
// can check that would make unverified input safe, and a verification done in
// here would be a verification against a digest that arrived with the bytes.
// See internal/computeimage, which is the only caller and which hashes the
// complete file against a digest compiled into this binary before opening it.
//
// Takes a Reader rather than a []byte because the file is ~190 MB and the
// machines that most need this are the ones that cannot spare that twice.
func (c *DockerClient) LoadImage(ctx context.Context, tarball io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiBase+"/images/load?quiet=1", tarball)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := c.long.Do(req)
	if err != nil {
		return fmt.Errorf("dcs: docker load: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&msg)
		return fmt.Errorf("dcs: docker load: HTTP %d: %s", resp.StatusCode, msg.Message)
	}
	// Like /build, /images/load answers 200 and then streams newline-delimited
	// JSON whose LAST object may be an error. A caller that trusted the status
	// code would report a successful load of an image the daemon rejected, and
	// the node would go on to advertise a workload it cannot run — which is the
	// exact failure this whole path exists to remove.
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err != nil {
			break // EOF, or output past the cap; either way there is no more to read
		}
		if msg.Error != "" {
			return fmt.Errorf("dcs: docker load failed: %s", msg.Error)
		}
	}
	return nil
}

func (c *DockerClient) Start(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
}

func (c *DockerClient) Stop(ctx context.Context, id string, grace int) error {
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/containers/%s/stop?t=%d", id, grace), nil, nil)
}

func (c *DockerClient) Remove(ctx context.Context, id string, force bool) error {
	path := "/containers/" + id + "?v=1"
	if force {
		path += "&force=1"
	}
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// ---------------------------------------------------------------------------
// Getting bytes in and out of a container
// ---------------------------------------------------------------------------
//
// A compute job is data in, data out. The container itself has no network (the
// hardened profile disables it outright), no bind mount and no volume, which
// leaves exactly one channel in each direction: Docker's archive endpoint,
// which extracts a tar into a container and reads one back out.
//
// This is deliberately the ONLY file channel. A bind mount would hand a
// submitted program a path on the volunteer's disk; a volume would outlive the
// job. A tar extracted into a per-job container that is destroyed afterwards
// leaves nothing behind and touches nothing outside itself.

// MaxArchiveBytes bounds a single retrieval.
//
// The container is the untrusted party here: it chooses the size of the file it
// writes, and the node reads that file into memory. Without a bound, a program
// that writes until the disk is full hands the node an out-of-memory kill as its
// result. The cap is the reason reading output is safe at all.
const MaxArchiveBytes = 16 << 20 // 16 MiB

var (
	// ErrArchiveMissing means the path does not exist in the container.
	//
	// Separate from a transport failure on purpose: "the job produced no output
	// file" is a normal, reportable outcome, while "the daemon did not answer"
	// is a broken node. A caller that cannot tell them apart either fails jobs
	// that legitimately wrote nothing, or reports a dead daemon as an empty
	// result.
	ErrArchiveMissing = errors.New("dcs: no such path in container")
	// ErrArchiveTooLarge means the container's file exceeded MaxArchiveBytes.
	// Also distinct: the job ran, and its output is simply too big to carry.
	ErrArchiveTooLarge = errors.New("dcs: container archive exceeds the maximum size")
)

// archivePath builds the endpoint URL. The container id and the in-container
// path both come from a caller that may be relaying a submitter's request, so
// both are escaped rather than concatenated — a path of "/work/x?foo=bar" must
// not become a second query parameter.
func (c *DockerClient) archivePath(id, containerPath string) string {
	return c.apiBase + "/containers/" + url.PathEscape(id) + "/archive?" +
		url.Values{"path": {containerPath}}.Encode()
}

// archiveErr turns a non-2xx archive response into a typed error.
func archiveErr(resp *http.Response, method, target string) error {
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrArchiveMissing, target)
	}
	var msg struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&msg)
	return fmt.Errorf("dcs: docker %s archive %s: HTTP %d: %s",
		method, target, resp.StatusCode, msg.Message)
}

// PutArchive extracts a tar into destDir inside the container.
//
// Called between Create and Start, which is the same window the agent uses to
// attach a network identity: the files are in place before the program's first
// instruction, so there is no window in which it could observe a half-delivered
// input and no race to lose.
//
// TWO DAEMON BEHAVIOURS CONSTRAIN THE CALLER, both verified against Docker 29
// rather than inferred from the documentation:
//
//   - the daemon refuses this call outright when the container's rootfs is
//     read-only, so the spec must set WritableRootfs;
//   - the tar is written through the image layer, NOT into the container's
//     mount namespace, so anything mounted over destDir at start (a tmpfs, for
//     instance) hides every file delivered here.
//
// Both failures are silent from the program's point of view — it simply finds
// no input — which is why they are written down at the call site.
func (c *DockerClient) PutArchive(ctx context.Context, id, destDir string, tarBytes []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.archivePath(id, destDir), bytes.NewReader(tarBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dcs: docker put archive %s: %w", destDir, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return archiveErr(resp, "put", destDir)
	}
	return nil
}

// GetArchive reads a path out of the container as a tar.
//
// Works on an exited container, which is the case that matters: a one-shot job
// writes its result and stops, and the file must still be retrievable
// afterwards. It reads the container's filesystem layer, so a file written to a
// tmpfs is gone by then — output has to land somewhere on the layer.
func (c *DockerClient) GetArchive(ctx context.Context, id, containerPath string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.archivePath(id, containerPath), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dcs: docker get archive %s: %w", containerPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, archiveErr(resp, "get", containerPath)
	}
	// One byte past the cap, so "exactly at the limit" is accepted and anything
	// larger is refused rather than silently truncated into a corrupt tar.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxArchiveBytes {
		return nil, fmt.Errorf("%w: %s", ErrArchiveTooLarge, containerPath)
	}
	return body, nil
}

// InspectState is the redacted projection. The raw Docker inspect response
// carries host paths, the hostname and network details; returning it wholesale
// would leak the worker's environment to whoever deployed the container, and
// would leak any NEW field a future Docker version adds. Whitelist, never
// blacklist.
type InspectState struct {
	ID        string `json:"id"`
	Image     string `json:"image"`
	Running   bool   `json:"running"`
	Paused    bool   `json:"paused"`
	Restarts  int    `json:"restarts"`
	OOMKilled bool   `json:"oom_killed"`
	ExitCode  int    `json:"exit_code"`
	StartedAt string `json:"started_at"`
	Health    string `json:"health,omitempty"`
}

// ContainerPID returns the container's main process PID, needed to enter its
// network namespace (netns_linux.go). A PID of 0 means the container is not
// running, so there is no namespace to join.
func (c *DockerClient) ContainerPID(ctx context.Context, id string) (int, error) {
	var raw struct {
		State struct {
			Pid     int  `json:"Pid"`
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &raw); err != nil {
		return 0, err
	}
	if !raw.State.Running || raw.State.Pid <= 0 {
		return 0, fmt.Errorf("dcs: container %s is not running", id)
	}
	return raw.State.Pid, nil
}

func (c *DockerClient) Inspect(ctx context.Context, id string) (InspectState, error) {
	var raw struct {
		ID    string `json:"Id"`
		Image string `json:"Image"`
		State struct {
			Running    bool   `json:"Running"`
			Paused     bool   `json:"Paused"`
			Restarting bool   `json:"Restarting"`
			OOMKilled  bool   `json:"OOMKilled"`
			ExitCode   int    `json:"ExitCode"`
			StartedAt  string `json:"StartedAt"`
			Health     *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		RestartCount int `json:"RestartCount"`
	}
	if err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &raw); err != nil {
		return InspectState{}, err
	}
	out := InspectState{
		ID: raw.ID, Image: raw.Image,
		Running: raw.State.Running, Paused: raw.State.Paused,
		Restarts: raw.RestartCount, OOMKilled: raw.State.OOMKilled,
		ExitCode: raw.State.ExitCode, StartedAt: raw.State.StartedAt,
	}
	if raw.State.Health != nil {
		out.Health = raw.State.Health.Status
	}
	return out, nil
}

// Wait blocks until the container exits and returns its exit code.
//
// Used by one-shot workloads — a submitted program runs, exits, and its status
// is the answer. Long-lived deployments poll Inspect instead; this is the case
// where "when is it finished" is the whole question.
func (c *DockerClient) Wait(ctx context.Context, id string) (int, error) {
	var raw struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	if err := c.do(ctx, http.MethodPost, "/containers/"+id+"/wait", nil, &raw); err != nil {
		return -1, err
	}
	if raw.Error != nil && raw.Error.Message != "" {
		return raw.StatusCode, fmt.Errorf("dcs: container wait: %s", raw.Error.Message)
	}
	return raw.StatusCode, nil
}

// MaxLogBytes caps what a single container's output may occupy.
//
// A program that prints in a loop would otherwise fill the volunteer's disk
// through the one channel it is allowed. The cap is not a formatting choice; it
// is the reason collecting output is safe at all.
const MaxLogBytes = 1 << 20 // 1 MiB

// Logs returns a finished container's stdout and stderr, separated.
//
// Docker multiplexes both onto one stream with an 8-byte header per frame whose
// first byte is the stream id. Concatenating the raw bytes would interleave the
// headers into the output as binary garbage, which is why this demultiplexes
// rather than simply reading the body.
func (c *DockerClient) Logs(ctx context.Context, id string) (stdout, stderr []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.apiBase+"/containers/"+id+"/logs?stdout=1&stderr=1", nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("dcs: logs: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxLogBytes+1))
	if err != nil {
		return nil, nil, err
	}
	return demuxDockerStream(body)
}

// demuxDockerStream splits Docker's multiplexed log framing.
//
// Frame: [stream_id(1)][000][size(4, big-endian)][payload]. A truncated final
// frame is returned as what was read rather than treated as an error — the
// output was capped on purpose, and losing the whole log because the last frame
// was clipped would defeat the point of capping it.
func demuxDockerStream(body []byte) (stdout, stderr []byte, err error) {
	for len(body) >= 8 {
		size := int(binary.BigEndian.Uint32(body[4:8]))
		if size < 0 || 8+size > len(body) {
			// Truncated by the cap: take what is there.
			payload := body[8:]
			if body[0] == 2 {
				stderr = append(stderr, payload...)
			} else {
				stdout = append(stdout, payload...)
			}
			break
		}
		payload := body[8 : 8+size]
		if body[0] == 2 {
			stderr = append(stderr, payload...)
		} else {
			stdout = append(stdout, payload...)
		}
		body = body[8+size:]
	}
	return stdout, stderr, nil
}
