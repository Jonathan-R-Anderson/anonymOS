# Volunteer gateway operations

## Architecture

The storage client keeps one persistent libp2p Ed25519 identity. Kademlia and
shard exchange remain I2P-only. Gateway verification is the deliberate
exception: candidates contact admitted probes over direct HTTPS so probes see
the candidate's real source address and can connect back to that exact address
on public TCP 443.

Roles are configuration-driven:

- ordinary peers have both `gateway.enabled` and `gateway.probe_enabled` false;
- candidates enable `gateway.enabled`;
- probes enable `gateway.probe_enabled` and set a stable `probe_network` trust
  domain (operator/ASN/prefix);
- verified gateways are candidates whose current signed results meet quorum;
- the separate server-side gateway controller owns all authoritative DNS
  access; the storage binary contains no DNS provider login or mutation path.

One process may be a candidate and probe, but its own probe result never counts.

## Verification flow

1. The candidate signs a short-lived hostname reservation with its persistent
   node identity. The controller deterministically derives
   `gw-<identity-hash>.syndichan.org`, points it only at the observed request
   source IP, and returns after the DNS provider accepts the change.
2. The candidate confirms that public DNS resolves its assigned name to that
   exact address, then starts exact-host ACME and its TLS listener.
3. It signs a short-lived request containing its explicitly configured public
   addresses. Only port 443 is accepted.
4. Each probe accepts the request only when its TCP source address equals the
   claimed address. This prevents victim-address SSRF.
5. The probe connects to that literal address while validating TLS against
   `public_hostname`; redirects are forbidden.
6. It fetches the signed identity, submits a signed one-use challenge, checks
   `/readyz`, then signs its result.
7. The candidate requires three distinct admitted identities across two
   configured network trust domains by default.
8. It signs a five-minute registration and submits it directly to
   `https://syndichan.org/api/v1/gateways/register`. The server ignores claimed
   addresses, derives the HTTPS source IP, and independently checks TCP 443,
   TLS hostname validity, HTTP 200, and `X-Gateway-Version`.
9. Only after server acceptance is it published under
   `/syndichan-gateway/<node-id>` in Kademlia. Every DHT reader independently
   validates the gateway signature, probe signatures, expiry, quorum, address
   policy, and DHT-key binding.
10. The server reconciles its verified healthy registry with Name.com. Durable
    record ownership prevents unrelated DNS records from entering the diff.

Address families are authorized independently. A dual-stack node must meet the
full configured probe and network quorum over its IPv4 literal before IPv4 is
advertised, and independently over its IPv6 literal before IPv6 is advertised.
A successful IPv4 path is never evidence that the IPv6 path is reachable.

## Candidate

Edit the generated `config.json` using `gateway.example.json` as a reference.
Set a real public IP in `public_addresses`, three or more HTTPS probe origins,
the admitted probe node IDs/public keys, and either:

- `tls.mode: existing` with a browser-trusted per-node certificate and key; or
- `tls.mode: acme` to reserve a deterministic `gw-` name and issue automatically; or
- `tls.mode: reverse_proxy`, with nginx/Caddy/HAProxy forwarding public 443 to
  the configured private listener.

Then:

```sh
syndichan-node -gateway-enable
syndichan-node -gateway-status
syndichan-node
```

Forward TCP 443 at the router and permit it through host, IPv6, and cloud
firewalls. A listening socket or UPnP mapping never counts as verification.

### Two ways an address gets proven

`gateway.external_verification.enabled` selects which check gates registration.
Registration itself always happens when `gateway.enabled` is true.

| | `enabled: true` | `enabled: false` |
| --- | --- | --- |
| Peer probe quorum | required (`probe_urls` ≥ `minimum_successful_probes`, ≥ 2 networks) | not run |
| Controller connect-back | yes | yes |
| DNS publication | after both | after the controller's own check |
| Reports `gateway_verified` | yes, once quorum passes | never |
| Registration carries probe results | yes | no (`successful_probes: 0`) |
| Accepted by `DHTValidator` | yes | no |

The second mode exists because a network with no probe fleet cannot bootstrap
its first gateway otherwise: the quorum requires probes, and probes are other
volunteers who must themselves be running. It is not a way to skip
reachability checking — the controller still connects back to the derived
source address and requires HTTP 200 with `X-Gateway-Version` on `/readyz`
before it will publish DNS. What it gives up is the independent multi-network
opinion, which is exactly why such a node never claims to be verified and its
registration is refused by the DHT validator.

## Dedicated gateway host

`-gateway-only` is a distinct runtime role, resolved from the command line
before any configuration is read. The process does not open the shard/object
store, accept or replicate shards, start S3 on 9000, start the dashboard on
9090, open I2P, or join the storage DHT.

It does send the five-minute presence heartbeat, signed by the same identity
and carrying `capacity_bytes: 0`. Presence is a property of the node, not of
the storage role: without it a dedicated gateway would be invisible to the
operator. Zero capacity is what distinguishes it — the frontend counts it as a
gateway, excludes it from the storage-node count, and adds nothing to network
capacity.

Because the role is decided first, a gateway-only config is validated against
gateway settings only. It needs no S3 credentials, capacity, erasure layout,
dashboard address, or I2P endpoints, and `config.json` on such a host should
contain none of them. It keeps a persistent Ed25519 identity under `-data-dir`
and posts its signed registration straight to the controller over HTTPS.
Public TCP 443 is required; public TCP 80 is required as well when
`gateway.tls.mode` is `acme`.

```sh
/usr/local/bin/syndichan-node \
  -gateway-only \
  -config /var/lib/syndichan/config.json \
  -data-dir /var/lib/syndichan/data
```

Startup logs the resolved role and the exact config path it loaded, which is
the fastest way to confirm a service unit is reading the file you think it is.

For the packaged systemd unit, use a drop-in so package updates cannot erase
the role selection:

```sh
sudo systemctl edit syndichan-node
```

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/syndichan-node -gateway-only -config /var/lib/syndichan/config.json -data-dir /var/lib/syndichan/data
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now syndichan-node
```

Never run a second copy alongside the service; only one process can own 80 and
443. Confirm the role took effect:

```sh
systemctl show syndichan-node -p ExecStart
ss -lnt | grep -E ':80 |:443 |:9000 |:9090 '
curl --fail https://gw-NODE-ID.syndichan.org/readyz
```

Only 80/443 may be present; 9000 and 9090 must be absent. `/readyz` must return
200 before the controller admits the gateway to the shared DNS answer set; 503
means the listener is not ready or the gateway is draining.

## Probe

A probe needs a publicly reachable TLS listener too. Set:

```json
{
  "gateway": {
    "enabled": false,
    "probe_enabled": true,
    "probe_network": "operator-a/as64500"
  }
}
```

Install its public key in each candidate's `trusted_probes`. Run the ordinary
binary; `/probe/verify` appears only when this role is enabled.

## Server-side DNS controller

The controller is deployed from `../gateway-controller` and
`../k8s/gateway-controller`. Name.com credentials are injected only into that
server workload through Kubernetes Secrets. They are not accepted by or
needed on a volunteer node. The client setting `registration_api` is a public,
credential-free HTTPS URL and authentication uses the node signature.

On graceful drain the client posts a signed unregister statement before its
DHT draining record. A hard crash is removed after registration expiry or
three consecutive server health failures.

## Automatic updates with rollback (Linux gateway)

A five-minute systemd updater is included for a dedicated gateway whose whole
installation lives under one normal user's home directory:

```text
/home/ubuntu/syndichan-node/
├── bin/{syndichan-node, syndichan-node.previous, update-from-github}
├── config/config.json
├── data/
├── source.git
├── deployed.sha
└── update-status
```

Use
[`syndichan-node-gateway-home.service`](packaging/systemd/syndichan-node-gateway-home.service)
for the gateway plus
[`syndichan-node-update.service`](packaging/systemd/syndichan-node-update.service)
and
[`syndichan-node-update.timer`](packaging/systemd/syndichan-node-update.timer)
for updates. Replace the example `/readyz` hostname in the update service with
the controller-assigned `gw-...syndichan.org` name before enabling it.

The updater never installs a downloaded opaque executable. It fetches `main`
into a bare mirror, exports the exact commit to a temporary directory, runs
`go test ./...`, builds with `CGO_ENABLED=0`, loads the real configuration in a
non-listening preflight, keeps the current binary as `syndichan-node.previous`,
atomically installs the candidate and restarts the service, accepts the commit
only once public `https://gw-.../readyz` succeeds, and otherwise restores and
restarts the previous binary automatically.

```sh
sudo install -m 0755 scripts/update-from-github.sh \
  /home/ubuntu/syndichan-node/bin/update-from-github
sudo install -m 0644 packaging/systemd/syndichan-node-gateway-home.service \
  /etc/systemd/system/syndichan-node.service
sudo install -m 0644 packaging/systemd/syndichan-node-update.service \
  /etc/systemd/system/
sudo install -m 0644 packaging/systemd/syndichan-node-update.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now syndichan-node syndichan-node-update.timer
```

Inspect state, or force one check:

```sh
cat /home/ubuntu/syndichan-node/update-status
systemctl list-timers syndichan-node-update.timer
sudo systemctl start syndichan-node-update.service
sudo journalctl -u syndichan-node-update.service -n 100 --no-pager
```

Requires `git`, `go`, `curl`, `tar`, `flock`, and GNU `timeout`. No GitHub
credential is needed or stored. This deliberately makes the configured branch a
remote-code deployment channel — the updater unit builds and tests code from it
as root — so protect `main` with required review. A successful update refreshes
the updater script itself but never rewrites its systemd privilege boundary.

## Diagnostics

```sh
syndichan-node -gateway-status
curl --fail https://gateway.example.com/healthz
curl --fail https://gateway.example.com/readyz
openssl s_client -connect PUBLIC_IP:443 -servername gateway.example.com
```

If local health works but external probes time out, check router forwarding,
host/cloud firewalls, CGNAT (`100.64.0.0/10`), double NAT, ISP filtering, and
IPv6 firewall policy. If TLS fails, correct the certificate chain, hostname,
and reverse-proxy SNI configuration. No code path disables TLS validation.

## Tests

```sh
cd storage-client
go test ./...
go vet ./...
```

Tests cover restricted IP ranges, CGNAT, signature binding, self-verification,
network diversity, replay rejection, health transitions, DHT record selection,
signed registration requests, I2P-only peer addresses, signed heartbeats,
encrypted transfer leases, S3 compatibility, storage quotas, and UI controls.
