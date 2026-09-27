package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/dcs"
)

// dockerComposeRunner runs vulhub-style docker-compose challenges by shelling out
// to the Docker Compose CLI. The node's single-container path talks to the Docker
// Engine API directly; compose is a different beast (multi-service, its own
// network, dependency ordering), so reusing the mature CLI is far safer than
// reimplementing it. It requires `docker compose` (v2 plugin) or `docker-compose`
// (v1) on the worker host -- the same host that already has Docker for the
// single-container path.
//
// Containment: before `up`, every host port publish is stripped from the compose
// file (see dcs.SanitizeComposeForContainment), so a lab binds nothing on the
// worker's clearnet. The only way in is the I2P destination the agent attaches to
// the primary service's container.
type dockerComposeRunner struct {
	baseDir  string   // project working dirs live under here
	endpoint string   // DOCKER_HOST for the CLI (matches the node's docker_endpoint)
	bin      []string // ["docker","compose"] or ["docker-compose"]
	logf     func(string, ...any)
}

func newDockerComposeRunner(baseDir, endpoint string, logf func(string, ...any)) (*dockerComposeRunner, error) {
	bin, err := detectComposeCLI()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, err
	}
	return &dockerComposeRunner{baseDir: baseDir, endpoint: endpoint, bin: bin, logf: logf}, nil
}

// detectComposeCLI prefers the v2 plugin (`docker compose`) and falls back to the
// v1 standalone (`docker-compose`).
func detectComposeCLI() ([]string, error) {
	if _, err := exec.LookPath("docker"); err == nil {
		if err := exec.Command("docker", "compose", "version").Run(); err == nil {
			return []string{"docker", "compose"}, nil
		}
	}
	if p, err := exec.LookPath("docker-compose"); err == nil {
		return []string{p}, nil
	}
	return nil, fmt.Errorf("neither `docker compose` nor `docker-compose` is installed")
}

func (r *dockerComposeRunner) env() []string {
	env := os.Environ()
	if r.endpoint != "" {
		env = append(env, "DOCKER_HOST="+r.endpoint)
	}
	return env
}

func (r *dockerComposeRunner) projectDir(project string) string {
	return filepath.Join(r.baseDir, project)
}

// Up writes the project, strips host ports, brings it up (pulling images from the
// registry), and returns the primary service's container id.
func (r *dockerComposeRunner) Up(ctx context.Context, project string, files []dcs.BuildFile, primaryPort int, env []string) (string, error) {
	dir := r.projectDir(project)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// The files were validated by UnpackComposeContext (regular files, safe
	// relative paths), so writing them out is safe.
	composeName := ""
	for _, f := range files {
		dst := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, f.Data, 0o600); err != nil {
			return "", err
		}
		if composeName == "" && isComposeFileName(f.Path) {
			composeName = f.Path
		}
	}
	if composeName == "" {
		return "", fmt.Errorf("compose context has no compose file")
	}
	composePath := filepath.Join(dir, filepath.FromSlash(composeName))

	raw, err := os.ReadFile(composePath)
	if err != nil {
		return "", err
	}
	sanitized, primarySvc, err := dcs.SanitizeComposeForContainment(raw, primaryPort)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(composePath, sanitized, 0o600); err != nil {
		return "", err
	}

	// Inject per-boot env (e.g. a random LAB_SECRET) into the primary service via
	// a compose override that MERGES onto whatever the project already defines.
	// This gives every launch a unique secret inside the box without editing the
	// upstream compose file, so answers derived from it can't be shared.
	composeFiles := []string{composeName}
	if len(env) > 0 && primarySvc != "" {
		overrideName := "docker-compose.syndichan-env.yml"
		if werr := os.WriteFile(filepath.Join(dir, overrideName),
			[]byte(composeOverrideYAML(primarySvc, env)), 0o600); werr != nil {
			return "", werr
		}
		composeFiles = append(composeFiles, overrideName)
	}

	if out, err := r.compose(ctx, dir, project, composeFiles, "up", "-d", "--remove-orphans"); err != nil {
		// Roll back a partial bring-up so nothing lingers.
		_, _ = r.compose(ctx, dir, project, composeFiles, "down", "-v", "--remove-orphans")
		return "", fmt.Errorf("up failed: %w: %s", err, strings.TrimSpace(out))
	}
	out, err := r.compose(ctx, dir, project, composeFiles, "ps", "-q", primarySvc)
	if err != nil {
		return "", fmt.Errorf("locate primary service %q: %w: %s", primarySvc, err, strings.TrimSpace(out))
	}
	cid := strings.TrimSpace(out)
	if i := strings.IndexByte(cid, '\n'); i >= 0 {
		cid = cid[:i]
	}
	if cid == "" {
		return "", fmt.Errorf("primary service %q produced no container", primarySvc)
	}
	if r.logf != nil {
		short := cid
		if len(short) > 12 {
			short = short[:12]
		}
		r.logf("dcs: compose project %s up; primary service %q -> container %s", project, primarySvc, short)
	}
	return cid, nil
}

// Down tears the whole project down and removes its working directory.
func (r *dockerComposeRunner) Down(ctx context.Context, project string) error {
	dir := r.projectDir(project)
	composeName := findComposeFileOnDisk(dir)
	if composeName != "" {
		_, _ = r.compose(ctx, dir, project, []string{composeName}, "down", "-v", "--remove-orphans")
	} else {
		// The working dir is gone (e.g. after a restart); tear down by the label
		// docker-compose stamps on every container of the project.
		r.labelTeardown(ctx, project)
	}
	_ = os.RemoveAll(dir)
	return nil
}

// compose runs `<bin...> -p <project> -f <file>... <args...>` in dir. Multiple
// compose files are passed in order so later ones (e.g. the env override) merge
// over earlier ones, matching docker-compose's own override semantics.
func (r *dockerComposeRunner) compose(ctx context.Context, dir, project string, composeFiles []string, args ...string) (string, error) {
	argv := append([]string{}, r.bin[1:]...)
	argv = append(argv, "-p", project)
	for _, f := range composeFiles {
		argv = append(argv, "-f", f)
	}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, r.bin[0], argv...)
	cmd.Dir = dir
	cmd.Env = r.env()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// composeOverrideYAML builds a minimal compose override that adds env vars to one
// service's environment. docker-compose deep-merges this onto the project, so the
// service's existing config is preserved and these keys are added/overridden.
func composeOverrideYAML(service string, env []string) string {
	var b strings.Builder
	b.WriteString("services:\n")
	b.WriteString("  " + yamlDoubleQuote(service) + ":\n")
	b.WriteString("    environment:\n")
	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		b.WriteString("      " + yamlDoubleQuote(parts[0]) + ": " + yamlDoubleQuote(parts[1]) + "\n")
	}
	return b.String()
}

// yamlDoubleQuote renders a value as a YAML double-quoted scalar, escaping the
// two characters that matter inside one (backslash and double-quote).
func yamlDoubleQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

// labelTeardown is the fallback when the compose file is gone: remove every
// container docker-compose labelled with this project, using plain docker.
func (r *dockerComposeRunner) labelTeardown(ctx context.Context, project string) {
	filter := "label=com.docker.compose.project=" + project
	out, err := r.docker(ctx, "ps", "-aq", "--filter", filter)
	if err != nil {
		return
	}
	for _, id := range strings.Fields(out) {
		_, _ = r.docker(ctx, "rm", "-f", "-v", id)
	}
}

func (r *dockerComposeRunner) docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = r.env()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func isComposeFileName(path string) bool {
	base := path
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	for _, name := range dcs.ComposeFileNames {
		if base == name {
			return true
		}
	}
	return false
}

func findComposeFileOnDisk(dir string) string {
	for _, name := range dcs.ComposeFileNames {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return name
		}
	}
	return ""
}
