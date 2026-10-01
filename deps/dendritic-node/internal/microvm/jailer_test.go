//go:build linux

package microvm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A jail around root is not confinement. Refused rather than warned about,
// because a configuration that LOOKS confined and is not is worse than an
// obviously unconfined one.
func TestJailingAsRootIsRefused(t *testing.T) {
	j := DefaultJail()
	j.UID = 0
	if err := j.Validate(); err == nil {
		t.Fatal("accepted uid 0 as a confinement")
	}
	j = DefaultJail()
	j.GID = 0
	if err := j.Validate(); err == nil {
		t.Fatal("accepted gid 0 as a confinement")
	}
}

func TestDefaultJailIsValidAndUnprivileged(t *testing.T) {
	j := DefaultJail()
	if err := j.Validate(); err != nil {
		t.Fatalf("the default jail is invalid: %v", err)
	}
	if j.UID == 0 || j.GID == 0 {
		t.Fatal("the default jail runs as root")
	}
	// nobody is shared with every other unprivileged service on the machine, so
	// a VMM escape would land as a user that may already own something.
	if j.UID == 65534 || j.GID == 65534 {
		t.Error("the default jail uses the shared 'nobody' uid")
	}
}

func TestEmptyConfigIsRefused(t *testing.T) {
	if err := (JailConfig{}).Validate(); err == nil {
		t.Fatal("an empty jail configuration validated")
	}
	if ok, why := (JailConfig{}).Available(); ok || why == "" {
		t.Fatal("an empty configuration reported available with no reason")
	}
}

// The chrooted process sees different paths than the host. Returning host paths
// produces a VM that fails to boot with file-not-found for a file that plainly
// exists.
func TestPreparedPathsAreInsideTheJail(t *testing.T) {
	base := t.TempDir()
	kernel := filepath.Join(base, "vmlinux.src")
	rootfs := filepath.Join(base, "rootfs.src")
	for _, p := range []string{kernel, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	j := DefaultJail()
	j.ChrootBase = base
	dir, inKernel, inRootFS, err := j.Prepare("job-1", kernel, rootfs)
	if err != nil {
		// Chown needs root; skipping is correct rather than failing, but the
		// path contract is still worth asserting when it does run.
		if strings.Contains(err.Error(), "needs root") {
			t.Skip("jail preparation needs root")
		}
		t.Fatal(err)
	}
	defer j.Cleanup(dir)

	if !strings.HasPrefix(inKernel, "/") || strings.Contains(inKernel, base) {
		t.Errorf("kernel path %q is a host path, not an in-jail one", inKernel)
	}
	if !strings.HasPrefix(inRootFS, "/") || strings.Contains(inRootFS, base) {
		t.Errorf("rootfs path %q is a host path, not an in-jail one", inRootFS)
	}
	// The artifacts must be COPIES: a bind mount would let a guest that found a
	// write path alter the images every later job boots from.
	if _, err := os.Stat(filepath.Join(dir, "vmlinux")); err != nil {
		t.Errorf("kernel was not copied into the jail: %v", err)
	}
}

// A leaked jail holds a copy of the rootfs, so leaking one per job fills the
// volunteer's disk — the failure that takes the node down rather than just this
// feature.
func TestCleanupRemovesTheJail(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "firecracker", "job-1", "root")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	j := DefaultJail()
	if err := j.Cleanup(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(dir)); !os.IsNotExist(err) {
		t.Fatal("the jail survived cleanup")
	}
	// Cleanup of nothing must not error, so it can be deferred unconditionally.
	if err := j.Cleanup(""); err != nil {
		t.Errorf("cleanup of an empty path errored: %v", err)
	}
}

// The command line must actually confine: new namespaces, a non-root uid, and
// no API socket.
func TestArgsRequestRealConfinement(t *testing.T) {
	args := strings.Join(DefaultJail().Args("/usr/local/bin/firecracker", "job-1", "/config.json"), " ")
	for _, want := range []string{"--new-pid-ns", "--uid 10001", "--gid 10001", "--no-api"} {
		if !strings.Contains(args, want) {
			t.Errorf("jailer args missing %q: %s", want, args)
		}
	}
}

// A job id arrives from the site and is not this node's to trust.
func TestJobIDIsSanitised(t *testing.T) {
	got := sanitiseJobID("../../etc/passwd; rm -rf /")
	for _, bad := range []string{"/", ";", " ", ".."} {
		if strings.Contains(got, bad) {
			t.Errorf("sanitised id %q still contains %q", got, bad)
		}
	}
	if sanitiseJobID("") == "" {
		t.Error("an empty id produced an empty jail name")
	}
	if len(sanitiseJobID(strings.Repeat("a", 200))) > 48 {
		t.Error("jail name is unbounded")
	}
}
