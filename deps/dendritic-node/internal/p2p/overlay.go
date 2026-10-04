package p2p

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
)

// Overlay is the AXON network this node's peer traffic runs over, in place of
// the I2P router it used to need beside it.
type Overlay struct {
	// Runtime is this node on the overlay. Required.
	Runtime *runtime.Runtime
	// Origin is the coordinator's AXON service address, if known. Coordinator
	// calls (leases, revocations, the bootstrap document) go to it through the
	// overlay; without it they go to the clearnet domain directly.
	Origin string
}

// overlayDialTimeout bounds one cold libp2p dial through AXON. It is DERIVED
// from §8.4's circuit budget (worst-case 3-hop build: 35 s), not inherited from
// the I2P dial it replaces. runtime.remote.connect runs its steps in sequence:
//
//	circuit to an HSDir + descriptor fetch     40 s
//	circuit to the rendezvous point            35 s
//	circuit to an introduction point           35 s
//	INTRODUCE1 -> RENDEZVOUS2, then Noise      10 s   (§9.3: 6 relay hops)
//	                                     -----------
//	                                          120 s
//
// NOT A MEASUREMENT, for the same reason store.shardFetchTimeout is not: no
// AXON circuit has been timed on a real network yet. Re-derive it from
// measured latency rather than relaxing it. A warm dial reuses the session and
// takes one round trip.
const overlayDialTimeout = 2 * time.Minute

// serviceSeedFile holds the seed of this node's AXON service, whose address is
// its libp2p address. Keeping the file keeps the address, exactly as
// i2p.destination did for the garlic address it replaces.
const serviceSeedFile = "axon.service.key"

// LoadOrCreateServiceSeed reads the 32-byte seed of an AXON service from path,
// creating it (mode 0600) on first use. Keeping the file keeps the address.
func LoadOrCreateServiceSeed(path string) ([32]byte, error) {
	return loadOrCreateServiceSeed(path)
}

// Overlay is the AXON runtime this node runs on, for anything else that needs
// a service of its own (a DCS container's address).
func (n *Node) Overlay() *runtime.Runtime {
	if n.overlay == nil {
		return nil
	}
	return n.overlay.Runtime
}

func loadOrCreateServiceSeed(path string) ([32]byte, error) {
	var seed [32]byte
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != len(seed) {
			return seed, fmt.Errorf("%s is %d bytes, want %d", path, len(raw), len(seed))
		}
		copy(seed[:], raw)
		return seed, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return seed, err
	}
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return seed, err
	}
	// O_EXCL: two processes racing to create the file must not end up with
	// two addresses, one of which the other process is already advertising.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateServiceSeed(path)
		}
		return seed, err
	}
	if _, err := file.Write(seed[:]); err != nil {
		file.Close()
		return seed, err
	}
	return seed, file.Close()
}

// coordinatorClient is how this node reaches the coordinator: through the
// overlay to its AXON service when the address is known, otherwise direct.
func (o Overlay) coordinatorClient(direct *http.Client) *http.Client {
	if o.Runtime == nil || o.Origin == "" {
		return direct
	}
	if _, err := identity.ParseAddress(o.Origin); err != nil {
		return direct
	}
	return &http.Client{
		Timeout: 75 * time.Second,
		Transport: &originTransport{
			origin: o.Origin,
			base: &http.Transport{
				DialContext:     o.Runtime.DialContext,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				// One session to the origin carries every stream; idle HTTP
				// connections on it cost the origin nothing to keep.
				MaxIdleConnsPerHost: 4,
			},
		},
	}
}

// originTransport sends a coordinator request to the origin's AXON service
// instead of to the host in its URL.
//
// Plain HTTP inside the overlay, and that is not a downgrade: the stream is
// encrypted end to end and the address is the service's own public key, so
// reaching it at all proves who answered -- which is everything TLS added on
// clearnet. The original host travels in the Host header, so an origin that
// serves several names still routes the request.
type originTransport struct {
	origin string
	base   http.RoundTripper
}

func (t *originTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme = "http"
	out.URL.Host = t.origin
	out.Host = req.URL.Host
	return t.base.RoundTrip(out)
}
