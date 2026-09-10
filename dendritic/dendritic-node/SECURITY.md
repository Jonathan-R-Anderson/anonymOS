# Security model

## Trust boundaries

- **Who holds plaintext, resolved (T11.5).** The COORDINATOR holds plaintext;
  the node never does. Content arrives already encrypted
  (`backend/services/content_keys.py`), so a storage node holds ciphertext it
  cannot read and has no per-object key to wrap. The local S3 gateway is the
  ingress for already-encrypted bytes, not an encryption origin.

  This paragraph previously said the gateway was "trusted with plaintext because
  it is the encryption origin", which contradicted
  `internal/store/types.go`'s statement that "the node no longer encrypts
  objects". The CODE was right and this file was stale; §1 of the roadmap flagged
  the ambiguity and T11.5 required it resolved rather than left to the reader.
- Volunteer peers are untrusted and receive only independently authenticated,
  content-addressed encrypted shards.
- `syndichan.org` is the discovery and allocation coordinator. Its HTTPS
  requests are forced through the configured local I2P HTTP proxy; TLS
  authenticates bootstrap documents and its Ed25519 key authenticates leases.
- Kademlia records and peer responses are untrusted hints. Every returned shard
  must match its SHA-256 ID before Reed-Solomon reconstruction.

## Cryptography

Encryption happens at the COORDINATOR, before bytes reach a node. Each object
receives a random 256-bit XChaCha20-Poly1305 key there; every chunk gets a random
192-bit nonce and associated data binding its bucket, key and index.

**The node's half of that is deliberately small.** It receives authenticated
ciphertext, splits it into Reed-Solomon shards, and gives each shard a SHA-256
content id. It holds no object key, wraps nothing, and cannot decrypt what it
stores. `Manifest.PlainSHA256` is the digest of the STORED (ciphertext) bytes —
named for the earlier design and kept as an end-to-end integrity check, not as a
digest of anything readable.

Recovery at the node verifies shard SHA-256 and Reed-Solomon reconstruction, and
stops there. XChaCha20-Poly1305 authentication and the final plaintext digest are
the coordinator's, because they need the key the node does not have.

## Ethereum BLS verification is an opt-in build capability (P12)

`internal/ethproof` can verify Ethereum sync-committee signatures — the P12
light-client path that lets a node authenticate chain data without trusting an
RPC. That verifier is built on `blst`, which is cgo and **cannot compile with
`CGO_ENABLED=0` on any target except wasm**. The release build is CGO-free by
design: seven platforms cross-compiled from one host, static, `-trimpath`.

So BLS is behind a build tag:

| build | tag | BLS |
|---|---|---|
| ordinary release (`build-release.sh`) | none | **not compiled** |
| P12 development and tests | `ethbls` | real `blst` implementation |

The tag **enables** BLS; its absence selects the stub. A forgotten tag therefore
produces the build that refuses to verify, never one that silently claims it
did.

**Released binaries do not contain BLS, and that is not a downgrade.** Nothing
in `cmd/syndichan-node` constructs a `BLSVerifier` — the only callers of
`NewBLSVerifier` are tests, and `LightClientState` takes its verifier as a
parameter. BLS arrived as a verified library capability with the consensus-spec
vectors and was never wired into a runtime path.

**The no-BLS build fails closed.** `NewBLSVerifier` returns a non-nil verifier
whose every method returns `ErrNoBLSSupport`, naming the missing `ethbls` tag.
It never returns nil (which would invite a `!= nil` bypass), never returns
success, and inspects no argument — rejecting only malformed input would imply
a well-formed one might pass. `ApplyUpdate`, `ApplyFinalityUpdate` and
`ApplyRotatingUpdate` propagate the refusal, so no update can be applied
unverified.

**If a future P12 feature needs BLS in production**, it must either ship an
`ethbls` build with a deliberate release architecture for it, or provide
another authenticated path. It must not treat `ErrNoBLSSupport` as a soft
failure, and must never fall back to an unverified source: a build without BLS
is incapable of claiming that BLS-protected consensus evidence was checked, and
that incapacity is the point.

## Admission and abuse controls

Remote `STORE` is denied unless:

- the coordinator is configured and its public key was learned over the fixed
  TLS bootstrap origin;
- the lease signature is valid and binds object ID, shard ID, size, recipient,
  and expiry;
- the lease lasts no more than one hour;
- the shard fits protocol and local capacity limits;
- neither its shard nor object ID is on the user's denial list;
- the bytes exactly match the leased SHA-256 shard ID.

The coordinator accepts lease requests only from configured origin peer IDs,
verifies their embedded Ed25519 libp2p identity signature, applies clock-skew,
nonce-replay, size, and per-minute limits, and binds each lease to one recipient.

## Local exposure

Configuration, identity, metadata, and master-key files use owner-only
permissions. Plaintext is encrypted while streaming into storage and is never
staged in a temporary file. The dashboard defaults to loopback and validates its
Host header. It may be moved to a private address (RFC1918, IPv4 link-local, or
IPv6 unique-local) so it can be reached from the operator's own network; that
requires `ui_password` of at least 12 characters, which is then demanded by HTTP
Basic auth on every request and compared in constant time. `0.0.0.0` and `::`
are refused with or without a password, because they also bind whatever public
interface the machine has now or acquires later, and publicly routable addresses
are refused outright. A non-loopback dashboard with no password configured
serves 503 rather than opening. The S3 API defaults to loopback; public binding
requires TLS.

The libp2p host registers only the custom I2P transport and advertises only
`/garlic32` multiaddresses. Bootstrap and provider records containing IP, DNS,
TCP, QUIC, WebSocket, or relay components are discarded. The SAM bridge and
I2P HTTP proxy are required to be local because SAM is ordinarily unencrypted
and unauthenticated. There is no direct-network fallback.

I2P conceals peer IP addresses from one another, but does not conceal traffic
timing, shard sizes, the fact that a user is running I2P from their ISP, or the
fact that two peers advertise the same encrypted shard ID. The coordinator's
HTTPS outproxy can observe the coordinator hostname, while the coordinator sees
the outproxy rather than the node's IP.

The five-minute frontend heartbeat is intentionally direct rather than I2P,
per product requirements. It therefore exposes the node's public egress IP to
`syndichan.org`, although the heartbeat table itself does not persist that IP.
The heartbeat is signed by the libp2p identity, freshness-checked, and
replay-protected. It uses the fixed User-Agent
`Syndichan-Storage-Client/1.0`.

## Volunteer gateway trust boundary

Gateway mode is opt-in and does not make the S3 API public. Public handlers
expose only liveness, readiness, signed identity, and bounded challenge
responses. A candidate cannot authorize itself as a probe. Probe requests and
results are signed, short-lived, identity-bound, and subject to an admitted
probe list and network-diversity quorum.

Probe connections use validated literal public addresses while retaining TLS
hostname verification, do not follow redirects, and reject local, private,
link-local, CGNAT, documentation, multicast, transition, and unspecified
targets. This prevents a DHT record from turning probes into an SSRF primitive.

DNS credentials never belong on volunteer nodes, in client configuration, or
in DHT records. The client sends a short-lived, nonce-protected statement to
the fixed credential-free registration API, signed by its persistent Ed25519
identity. The separate server derives the direct request source IP, verifies
TCP/TLS/HTTP availability, and is the only component allowed to call Name.com.
Its durable ownership table ensures it never updates or deletes unrelated DNS
records. A verified gateway remains untrusted with content: clients must retain
end-to-end encryption and content-hash verification.

## Kademlia availability advisory

The Go Kademlia implementation is covered by `GO-2024-3218`, an availability
advisory with no upstream fixed version: hostile DHT peers can attempt to hide
provider records. The client does not trust the DHT for integrity and does not
use it as its only lookup path. It protects the TLS-discovered bootstrap
connections and asks trusted bootstrap plus already-connected swarm peers
directly before using Kademlia provider hints. SHA-256 and AEAD verification
prevent a malicious routing response from substituting data, but a sufficiently
large eclipse attack can still delay availability. This residual availability
risk is inherent in the requested public Kademlia layer and must be included in
the production threat model.
