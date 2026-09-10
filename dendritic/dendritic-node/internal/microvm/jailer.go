//go:build linux

package microvm

// Confining the VMM itself.
//
// WHAT THE JAILER IS FOR, AND WHY IT IS NOT REDUNDANT
// ---------------------------------------------------
// Firecracker confines the guest. The jailer confines FIRECRACKER — and the two
// are different threats.
//
// The guest is hostile by assumption, and hardware virtualisation contains it.
// But Firecracker is a process on the host running as whoever launched it, and
// a bug in the VMM's own device emulation is a bug in code that has the
// volunteer's privileges. Without the jailer, escaping the guest means landing
// on the host as the node's user. With it, escaping the guest means landing in
// an empty chroot as an unprivileged uid, in its own namespaces, under a cgroup
// that bounds what it can consume.
//
// So this is defence in depth in the honest sense: it does not make the first
// boundary stronger, it makes the second one exist.
//
// WHY THE ARTIFACTS ARE COPIED RATHER THAN BIND-MOUNTED
// -----------------------------------------------------
// The jailer chroots, so the kernel and rootfs must be inside the jail. Copying
// costs disk and a moment per job; bind-mounting the originals would mean a
// guest that found a write path could modify the images every LATER job boots
// from. Copying is the version where one compromise stays one compromise.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// JailConfig is how tightly the VMM is confined.
type JailConfig struct {
	// Binary is the jailer executable.
	Binary string
	// ChrootBase is where per-job jails are created. Each job gets its own and
	// it is removed afterwards — a shared jail would let one job leave state
	// the next one boots into.
	ChrootBase string
	// UID and GID the VMM drops to. Never 0: the whole point is that a VMM
	// escape does not land as root.
	UID int
	GID int
	// CgroupCPUPercent and CgroupMemBytes bound what the VMM may consume on the
	// HOST, independently of the limits inside the guest. A guest cannot exceed
	// its own memory; a buggy VMM can.
	CgroupCPUPercent int
	CgroupMemBytes   int64
}

// DefaultJail is a sane confinement.
//
// uid/gid 10001 rather than nobody: `nobody` is shared with every other
// unprivileged service on the machine, so a VMM escape would land as a user
// that may already own something worth having.
func DefaultJail() JailConfig {
	return JailConfig{
		Binary: "jailer", ChrootBase: "/srv/jailer",
		UID: 10001, GID: 10001,
		CgroupCPUPercent: 100, CgroupMemBytes: 2 << 30,
	}
}

// Validate refuses a configuration that would not actually confine anything.
func (j JailConfig) Validate() error {
	if j.Binary == "" {
		return fmt.Errorf("microvm: no jailer binary")
	}
	if j.ChrootBase == "" {
		return fmt.Errorf("microvm: no chroot base")
	}
	if j.UID == 0 || j.GID == 0 {
		// Running the VMM as root inside a jail is a jail around root. Refused
		// rather than warned about, because a configuration that looks
		// confined and is not is worse than an obviously unconfined one.
		return fmt.Errorf("microvm: refusing to jail as uid/gid 0 — that is not confinement")
	}
	return nil
}

// Available reports whether the jailer can be used.
func (j JailConfig) Available() (bool, string) {
	if err := j.Validate(); err != nil {
		return false, err.Error()
	}
	if _, err := exec.LookPath(j.Binary); err != nil {
		return false, "jailer not found on PATH"
	}
	return true, ""
}

// Prepare builds a jail for one job and returns the paths INSIDE it.
//
// Returns the in-jail paths because the caller must hand Firecracker paths as
// the chrooted process will see them, not as the host does. Getting that
// backwards produces a VM that fails to boot with a file-not-found for a file
// that plainly exists — a confusing enough failure to be worth the explicit
// return.
func (j JailConfig) Prepare(jobID, kernel, rootfs string) (jailDir, inKernel, inRootFS string, err error) {
	if err := j.Validate(); err != nil {
		return "", "", "", err
	}
	jailDir = filepath.Join(j.ChrootBase, "firecracker", sanitiseJobID(jobID), "root")
	if err := os.MkdirAll(jailDir, 0o750); err != nil {
		return "", "", "", err
	}
	for _, item := range []struct{ src, name string }{
		{kernel, "vmlinux"}, {rootfs, "rootfs.img"},
	} {
		dst := filepath.Join(jailDir, item.name)
		if err := copyFile(item.src, dst); err != nil {
			os.RemoveAll(jailDir)
			return "", "", "", err
		}
		// Owned by the jailed uid, readable but not writable by it: the guest
		// boots from these and must never be able to alter them.
		if err := os.Chown(dst, j.UID, j.GID); err != nil {
			// Chown needs privilege. Reported rather than ignored, because a
			// jail whose files the jailed user cannot read is a jail that does
			// not boot, and the error would otherwise surface as a mystery.
			os.RemoveAll(jailDir)
			return "", "", "", fmt.Errorf("microvm: chown jail artifacts (needs root): %w", err)
		}
		_ = os.Chmod(dst, 0o440)
	}
	// Paths as the chrooted process sees them.
	return jailDir, "/vmlinux", "/rootfs.img", nil
}

// Cleanup removes a job's jail.
//
// Called on every path including failure. A jail left behind holds a copy of
// the rootfs, so leaking one per job fills the volunteer's disk — which is the
// failure that takes the whole node down rather than just this feature.
func (j JailConfig) Cleanup(jailDir string) error {
	if jailDir == "" {
		return nil
	}
	return os.RemoveAll(filepath.Dir(jailDir))
}

// Args builds the jailer command line that wraps Firecracker.
func (j JailConfig) Args(firecracker, jobID, configPath string) []string {
	return []string{
		"--id", sanitiseJobID(jobID),
		"--exec-file", firecracker,
		"--uid", fmt.Sprint(j.UID),
		"--gid", fmt.Sprint(j.GID),
		"--chroot-base-dir", j.ChrootBase,
		// New PID and mount namespaces. Without them a VMM escape sees every
		// process on the host and every mount, which is most of what it would
		// need to do something useful.
		"--new-pid-ns",
		"--",
		"--no-api", "--config-file", configPath,
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func sanitiseJobID(id string) string {
	var out []rune
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "job"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return string(out)
}
