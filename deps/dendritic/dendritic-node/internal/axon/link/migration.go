package link

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// F4 — connection migration with CID rotation (§6.2, §6.6, INVARIANT L1-3).
//
// WHAT quic-go ALREADY GUARANTEES, VERIFIED BY READING IT. v0.59.1's outgoing
// path manager asks for a connection ID before sending a PATH_CHALLENGE, and
// when the pool is empty `getConnID` returns false and it sends NOTHING. It does
// not fall back to the current ID. So L1-3's hard half -- "MUST NOT reuse a
// connection ID observed on any previous path" -- holds without anything here
// enforcing it, and re-enforcing it from outside would be a second copy of a
// rule the library already keeps.
//
// WHAT IT DOES NOT GUARANTEE, AND WHY THIS FILE EXISTS. The failure is SILENT.
// `Path.Probe` blocks until the context expires, and the caller sees a timeout
// indistinguishable from "the new path is unreachable". §6.6's threat model says
// a peer withholding connection IDs "can force link death at an address change
// -- a targeted, DETECTABLE DoS".
//
// THAT "DETECTABLE" IS NOT EARNED, AND CANNOT BE FROM OUTSIDE THE LIBRARY. The
// signal that would separate the two failures -- whether a PATH_CHALLENGE was
// actually sent -- lives on quic-go's unexported `pathOutgoing`, and `Path.Probe`
// returns `context.Cause(ctx)` either way. This was tried and abandoned rather
// than approximated, because a classifier that guessed would report a peer as
// hostile on an ordinary unreachable path.
//
// What IS enforceable is the PREDICTABLE half. The pool has a known depth and
// every unvalidated path holds an entry, so MigrationGuard counts outstanding
// probes and refuses the one that would exhaust it -- turning a silent stall
// into L1-3's prescribed outcome, "a link that cannot be migrated, not one that
// may be migrated unsafely".
//
// §6.2's `active_connection_id_limit = 8` IS NOT ACHIEVABLE ON quic-go v0.59.1,
// and the shortfall is worse than the source suggests. The library hardcodes
// `protocol.MaxActiveConnectionIDs = 4` with no way to set it from quic.Config
// -- and MEASURED against a real connection, only TWO extra paths validate
// concurrently, not the three that 4-minus-the-active-path would predict.
//
// So the guard is built on the measured figure and not on either the spec's or
// the library's. Reading a constant and trusting it is how a guard ends up
// green-lighting a probe the library cannot back, which is the single thing
// this one exists to prevent. L1-3 says the limit "exists to guarantee the pool
// is never empty at the moment of migration"; §6.2 asked for a margin of seven
// and the deployment gets two.

const (
	// MaxIdleTimeout is §6.2's max_idle_timeout.
	MaxIdleTimeout = 60 * time.Second
	// MaxUDPPayloadSize is §6.2's floor: no PMTU-dependent behaviour and no
	// per-path variation for an observer to key on.
	//
	// TAKEN FROM params, NOT REDECLARED. E13.4's audit caught the literal 1200
	// here on the first writing, and it was right to: §6.2's max_udp_payload_size
	// and §16's DatagramSize are THE SAME NUMBER for the same reason, and two
	// copies drift the moment either is retuned. This is the T14.3 finding
	// again, one section along.
	MaxUDPPayloadSize = params.DatagramSize
	// InitialMaxData is §6.2's connection-level credit.
	InitialMaxData = 4 << 20
	// InitialMaxStreamData is 64 KiB -- 64 cells in flight per circuit.
	InitialMaxStreamData = 64 << 10
	// InitialMaxStreamsBidi is §6.2's 512 circuits per link per direction.
	InitialMaxStreamsBidi = 512
	// InitialMaxStreamsUni is 0. "A node offering them is not speaking AXON."
	InitialMaxStreamsUni = 0

	// SpecActiveConnectionIDLimit is §6.2's stated 8.
	SpecActiveConnectionIDLimit = 8
	// LibraryActiveConnectionIDLimit is quic-go v0.59.1's hardcoded
	// protocol.MaxActiveConnectionIDs. It is not settable from quic.Config.
	LibraryActiveConnectionIDLimit = 4
	// MigrationPoolDepth is what the pool is WORTH IN PRACTICE, and it is the
	// number the guard is built on.
	//
	// IT IS MEASURED, NOT READ. TestPoolDepthMeasuredAgainstTheLibrary stages
	// paths against a real connection until the library stops validating them,
	// and it stops at TWO extra paths -- not the three that a hardcoded limit of
	// 4 minus one active path would predict. The constant and the behaviour
	// disagree, retirement timing being the likely reason, and the behaviour is
	// what a migration actually gets. Building the guard on the source constant
	// would let it green-light a probe the library cannot back, which is the one
	// thing it exists to prevent.
	//
	// So: 3, allowing two outstanding probes. Against §6.2's requested 8 this is
	// a MARGIN OF TWO where the spec asked for seven.
	MigrationPoolDepth = 3
)

// TransportProfile is §6.2's canonical wire profile.
//
// ONE PROFILE FOR THE WHOLE NETWORK, AND NO KNOBS. §12's fingerprinting table is
// explicit: "Transport parameters fixed by spec, not by config. No knob may
// change a byte that is visible before the handshake completes." A per-operator
// tunable here is a per-operator fingerprint, and a network where nodes are
// individually identifiable by their transport parameters has lost the property
// every other layer is paying for. So this function takes NO ARGUMENTS.
func TransportProfile() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout: MaxIdleTimeout,
		// Flow control, from §6.2. Initial and max are set equal so the window
		// never auto-tunes: an auto-tuned window is a per-connection behaviour
		// an observer can watch change, which is the same class of leak as a
		// configurable parameter.
		InitialStreamReceiveWindow:     InitialMaxStreamData,
		MaxStreamReceiveWindow:         InitialMaxStreamData,
		InitialConnectionReceiveWindow: InitialMaxData,
		MaxConnectionReceiveWindow:     InitialMaxData,
		MaxIncomingStreams:             InitialMaxStreamsBidi,
		MaxIncomingUniStreams:          InitialMaxStreamsUni,
		// PMTU discovery OFF: §6.2 fixes max_udp_payload_size at 1200 precisely
		// so there is no per-path size variation to observe. Leaving discovery
		// on would produce exactly that variation.
		DisablePathMTUDiscovery: true,
		// Keepalive under §6.6's 20 s relay-to-relay figure. The client guard
		// link is kept alive by P13's padding instead, which is why this is the
		// relay number and not the 15 s one.
		KeepAlivePeriod: 20 * time.Second,
		// 0-RTT IS NOT SET HERE, DELIBERATELY. The zero value is already false,
		// TestZeroRTTIsOff asserts that quic-go's default has not changed, and
		// T2.5's audit counts every reference to the field in this package --
		// correctly, since the only way it becomes true is if some code sets it,
		// and code that names the field is the thing to look for. Writing
		// `Allow0RTT: false` here would be a harmless line that makes the audit
		// unable to distinguish it from a harmful one.
	}
}

var (
	// ErrCIDStarved is L1-3's refusal, raised BEFORE a doomed probe is started.
	ErrCIDStarved = errors.New("axon/link: migration refused -- no unused connection ID is available, so migrating would either reuse one (INVARIANT L1-3) or stall silently; this link is treated as one that cannot be migrated")
	// ErrPathUnvalidated is the ordinary failure: the PATH_CHALLENGE went out
	// and nothing came back.
	ErrPathUnvalidated = errors.New("axon/link: migration failed -- the new path did not validate")
)

// MigrationOutcome is what a migration attempt turned into.
type MigrationOutcome uint8

const (
	// MigrationSucceeded: path validated and switched.
	MigrationSucceeded MigrationOutcome = iota
	// MigrationRefused: the guard would not start it. §6.6's named DoS, caught
	// in the one case it can be caught in -- see MigrationGuard.
	MigrationRefused
	// MigrationFailed: the probe was started and did not validate.
	//
	// THIS OUTCOME IS AMBIGUOUS AND THE AMBIGUITY IS NOT FIXABLE HERE. It covers
	// both "the network did not carry the new path" and "the peer withheld a
	// connection ID after we had already committed to probing". quic-go decides
	// between those internally and reports neither: Path.Probe returns
	// context.Cause(ctx) in both cases, and the signal that would separate them
	// (whether a PATH_CHALLENGE was actually sent) is on an unexported type.
	MigrationFailed
)

func (o MigrationOutcome) String() string {
	switch o {
	case MigrationSucceeded:
		return "succeeded"
	case MigrationRefused:
		return "refused-cid-starved"
	default:
		return "failed"
	}
}

// ProbeDeadline bounds a path probe.
const ProbeDeadline = 3 * time.Second

// MigrationGuard is INVARIANT L1-3, enforced in the only place it can be.
//
// WHAT IT CANNOT DO, STATED FIRST. It cannot observe the peer's connection-ID
// pool: quic-go tracks that internally and exposes nothing. So it cannot detect
// a peer that starves us DURING a probe, and §6.6's claim that a withheld-CID
// attack is "a targeted, DETECTABLE DoS" IS NOT EARNED on quic-go v0.59.1 --
// the detection would need a library change, and pretending otherwise would put
// a claim in the roadmap that the code cannot keep.
//
// WHAT IT DOES DO. The pool has a known depth, and every unvalidated path holds
// one entry. So the guard counts outstanding probes and REFUSES the one that
// would exceed the depth, rather than starting a probe that can only stall. That
// converts the predictable half of the failure from a silent three-second hang
// into L1-3's prescribed outcome: "treated as a link that cannot be migrated,
// not as one that may be migrated unsafely".
type MigrationGuard struct {
	// Depth is the usable pool. Defaults to MigrationPoolDepth, which is
	// MEASURED, not §6.2's 8 and not the library's own constant of 4.
	Depth int

	outstanding int
}

// depth returns the effective pool depth.
func (g *MigrationGuard) depth() int {
	if g.Depth > 0 {
		return g.Depth
	}
	return MigrationPoolDepth
}

// Begin reserves a pool entry, or refuses.
//
// One entry is always held back for the ACTIVE path. Spending the last ID on a
// probe would leave nothing to migrate to if the current path died mid-probe,
// which turns a defence into the failure it defends against.
func (g *MigrationGuard) Begin() error {
	if g.outstanding >= g.depth()-1 {
		return fmt.Errorf("%w: %d of %d entries already committed",
			ErrCIDStarved, g.outstanding, g.depth())
	}
	g.outstanding++
	return nil
}

// End releases a reservation, whatever the outcome.
func (g *MigrationGuard) End() {
	if g.outstanding > 0 {
		g.outstanding--
	}
}

// Outstanding is how many probes are in flight.
func (g *MigrationGuard) Outstanding() int { return g.outstanding }

// Migrate probes and switches to a new path under the guard.
func Migrate(ctx context.Context, g *MigrationGuard, conn *quic.Conn, tr *quic.Transport) (MigrationOutcome, error) {
	if g != nil {
		if err := g.Begin(); err != nil {
			return MigrationRefused, err
		}
		defer g.End()
	}

	path, err := conn.AddPath(tr)
	if err != nil {
		// AddPath refuses up front when the peer set disable_active_migration,
		// or when this side is the SERVER -- RFC 9000 has no server-initiated
		// migration, which is §6.6's CASE 2 and exactly why a responder's
		// address change kills its inbound links while an initiator's does not.
		return MigrationFailed, err
	}
	defer path.Close()

	probeCtx, cancel := context.WithTimeout(ctx, ProbeDeadline)
	defer cancel()

	if err := path.Probe(probeCtx); err != nil {
		return MigrationFailed, fmt.Errorf("%w: %w", ErrPathUnvalidated, err)
	}
	if err := path.Switch(); err != nil {
		return MigrationFailed, err
	}
	return MigrationSucceeded, nil
}
