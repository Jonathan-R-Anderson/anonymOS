package microvm

// The console byte cap.
//
// Here rather than in run.go because it has no Linux dependency: it counts
// bytes into a slice. run.go is //go:build linux for KVM and Firecracker, and
// leaving this there meant the two tests covering it could only compile on
// Linux — a portable behaviour tested on one platform for no reason.
//
// Not in config.go either: that file builds a machine config, and a console
// writer is not part of one.

// capped is an io.Writer that stops at a limit instead of growing forever.
//
// Silently discarding the overflow is deliberate: the alternative is failing
// the job because it was chatty, which turns a log-volume policy into a
// correctness one.
type capped struct {
	buf   []byte
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) <= room {
			c.buf = append(c.buf, p...)
		} else {
			c.buf = append(c.buf, p[:room]...)
			c.over = true
		}
	} else {
		c.over = true
	}
	// Always reports the full write. Returning short would make the child see
	// a write error on its console and possibly die — the cap exists to protect
	// the host's disk, not to change the guest's behaviour.
	return len(p), nil
}

func (c *capped) Bytes() []byte {
	if !c.over {
		return c.buf
	}
	return append(c.buf, []byte("\n[console truncated at "+
		itoa(c.limit)+" bytes]\n")...)
}

// itoa exists so Bytes() can build its truncation notice without pulling strconv
// into this file. Moved with capped because that method is its only caller —
// leaving it in the Linux-only run.go would mean capped had not really moved.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
