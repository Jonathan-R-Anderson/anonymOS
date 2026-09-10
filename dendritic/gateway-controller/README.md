# Syndichan gateway controller

This is the authoritative, server-only half of volunteer gateway discovery.
Storage clients send signed registration statements here. The controller
derives the request source address, independently verifies the gateway, stores
health state in PostgreSQL, and reconciles controller-owned `A` and `AAAA` records through
the official Name.com Core API.

The storage client never receives a Name.com username, token, session, or
general-purpose DNS capability.

## Trust and request flow

```text
storage client (Ed25519 signed request, no shared secret)
    -> syndichan.org ingress (overwrites X-Forwarded-For)
    -> registration API (derives the public source IP and checks replay/rate limits)
    -> direct TCP 443 + TLS hostname + GET /readyz verification
    -> PostgreSQL verified/healthy gateway registry
    -> ownership-scoped Name.com DNS reconciliation
```

Registration is direct Internet HTTPS rather than I2P by design: the source
address seen by the trusted ingress is the only address eligible for probing
and publication. Client-supplied registration addresses are retained for the
signed DHT protocol but ignored by this service.

Only host labels beginning with `subdomain_prefix-` and the one exact
`public_hostname` are eligible. Existing records are never adopted. The `managed_dns_records`
table records the exact Name.com record ID created by this controller; update
and deletion require both the host and record ID to match. This prevents an
unrelated or manually replaced record from entering a destructive diff.

## API

- `POST /api/v1/gateways/reserve` assigns the node's deterministic ACME name.
- `POST /api/v1/gateways/register` accepts the storage client's signed envelope.
- `POST /api/v1/gateways/unregister` immediately makes a gateway ineligible and
  triggers DNS removal.
- `GET /api/v1/gateways` returns verified healthy gateways sorted by latency.
- `GET /metrics` exposes Prometheus counters, gauges, and verification latency.
- `GET /healthz` is the process liveness endpoint.

Registrations are limited to five per minute per source IP. Set `REDIS_URL` for
a shared limiter across replicas; without Redis the limiter is per process.
Ed25519 identity binding, a 90-second timestamp window, one-use nonce table,
monotonic registration sequence, public-address policy, and external verification
are all enforced before DNS publication.

## Name.com credentials

Create an API token in the Name.com account's API settings. Use a dedicated
automation account where possible. Test first with Name.com's sandbox and
`https://api.dev.name.com/core/v1`; production uses
`https://api.name.com/core/v1`.

The Core API uses HTTP Basic authentication with the account username and API
token. This service reads them from two places only, in this order:

1. the environment — `NAMECOM_USERNAME` and `NAMECOM_API_TOKEN`;
2. the stack's shared `.env` file, which holds the same two keys.

The `.env` file is the source of truth. `ENV_FILE_CANDIDATES` in `config.py`
resolves the first of `/secret/.env`, `./.env`, `../.env` that exists, and
`GATEWAY_ENV_FILE` overrides the search. Only `NAMECOM_USERNAME`,
`NAMECOM_API_TOKEN` and `NAMECOM_API_URL` are taken from it: that file also
defines `DOMAIN` and `TRUSTED_PROXY_CIDRS` for the app tier, and letting it
override the reviewed zone or the proxy trust boundary here would be a silent
security change. An injected environment variable still wins over the file, so
the Kubernetes Secret projected from `.env` remains authoritative in the
cluster.

Do not place either value in `config.yaml`, container images, Kubernetes
ConfigMaps, client settings, or command-line arguments. `config.py` rejects
non-empty `namecom` credentials in YAML. Treat `.env` as secret material:
it is readable by everyone who can read the repository checkout it lives in.

The controller uses:

```text
GET    /core/v1/domains/{domainName}/records
POST   /core/v1/domains/{domainName}/records
PUT    /core/v1/domains/{domainName}/records/{id}
DELETE /core/v1/domains/{domainName}/records/{id}
```

`500`, `502`, and `504` responses use bounded exponential backoff. A `429`
stops immediately so a scheduled pass cannot consume more provider quota; the
public reservation API returns `503` plus `Retry-After` and clients wait before
signing a fresh attempt.
Ambiguous create `504` responses are followed by a list/read before retry so
the controller cannot create duplicate records. TTL cannot be below Name.com's
300-second minimum.

## Configuration

Copy `config.example.yaml` to `config.yaml`. This file contains public policy
only. Runtime settings override YAML using uppercase environment names:

| Setting | Purpose |
| --- | --- |
| `DOMAIN` | Authoritative Name.com zone |
| `PUBLIC_HOSTNAME` | Exact shared browser-facing hostname |
| `SUBDOMAIN_PREFIX` | Controller-owned host prefix, default `gw` |
| `TTL` | DNS TTL, minimum 300 |
| `HEALTH_CHECK_INTERVAL` | External recheck interval |
| `DNS_SYNC_INTERVAL` | Name.com reconciliation interval |
| `GATEWAY_TIMEOUT` | TCP/TLS/HTTP timeout |
| `REGISTRATION_LIFETIME` | Maximum accepted statement lifetime |
| `MAX_GATEWAYS` | Registry admission ceiling |
| `MAX_ANSWERS` | Maximum healthy gateway answers on `PUBLIC_HOSTNAME` |
| `DATABASE_URL` | Async SQLAlchemy PostgreSQL URL |
| `REDIS_URL` | Optional shared rate-limiter URL |
| `NAMECOM_USERNAME` | Server-secret Name.com username |
| `NAMECOM_API_TOKEN` | Server-secret Name.com API token |
| `GATEWAY_ENV_FILE` | Override the `.env` path searched for the two above |

`TRUSTED_PROXY_CIDRS` is security-sensitive public configuration. Honor
`X-Forwarded-For` only from the ingress network, and configure ingress to
overwrite the header with `$remote_addr`. Never trust a client-appended chain.

## Run locally

Python 3.12 is required:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
cp config.example.yaml config.yaml
export DATABASE_URL='postgresql+asyncpg://gateway:password@127.0.0.1/gateway'
uvicorn backend.api:app --host 127.0.0.1 --port 8080
```

The credentials come from the repository root `.env` (`../.env`) without any
further setup. Point `GATEWAY_ENV_FILE` elsewhere to use a different file.

For local integration only, `docker compose up --build` starts PostgreSQL and
the controller. It requires `GATEWAY_DB_PASSWORD` in the calling process and
mounts `../.env` read-only at `/secret/.env`. Kubernetes is the production
deployment.

Run tests without contacting Name.com:

```sh
pytest -q
```

## Kubernetes production deployment

Build `gateway-controller/Dockerfile`, place the image in the cluster registry,
create the two Secrets described in
[`../k8s/gateway-controller/README.md`](../k8s/gateway-controller/README.md),
and apply the manifest. Then apply the nginx ConfigMap so the three public API
routes reach the controller.

The manifest runs two replicas. PostgreSQL persists registrations, replay
nonces, health state, and DNS ownership. A PostgreSQL advisory transaction lock
serializes DNS reconciliation across replicas. Configure Redis to enforce the
registration limit globally.

Keep `/metrics` internal and alert on:

- rising `syndichan_gateway_registration_failures_total`;
- rising `syndichan_gateway_verification_failures_total`;
- sustained Name.com request failures in logs;
- unexpected changes in `syndichan_gateway_dns_records_total`;
- nonzero `syndichan_gateway_dns_divergence_records`;
- rising `syndichan_gateway_dns_reconcile_failures_total` or
  `syndichan_gateway_dns_provider_rate_limits_total`;
- nonzero `syndichan_gateway_network_policy_divergence_addresses` or rising
  `syndichan_gateway_network_policy_reconcile_failures_total`;
- zero healthy gateways.

## Origin trust synchronization

When `network_policy_sync_enabled` is true, the controller reconciles the
dedicated origin listener's Kubernetes NetworkPolicy every 30 seconds. Only
literal `/32` and `/128` addresses from healthy, verified, registered gateways
are admitted to TCP 9443. An empty registry removes the 9443 ingress rule and
therefore denies that port; it never creates an allow-all fallback.

nginx accepts PROXY v2 only on this dedicated listener. Its
`set_real_ip_from` scope can cover all address families because the
NetworkPolicy is the outer source-authentication boundary. Ordinary public
TCP 443 neither accepts PROXY protocol nor shares this trust. The controller's
ServiceAccount can only get and patch the single named NetworkPolicy; it cannot
read Secrets or mutate any other workload.

## Health removal and crash recovery

Every health pass repeats TLS and HTTP verification against the stored source
IP while using the DNS hostname for SNI/certificate validation. One or two
failures retain the DNS record. Three consecutive failures make the gateway
ineligible and the next synchronization removes its owned record. Expired
registrations and explicit unregister requests are also removed.

All desired state and DNS ownership survive controller restarts. On startup,
the scheduler resumes health checks and reconciliation. If Name.com is
temporarily unavailable, PostgreSQL remains authoritative and a later pass
converges. Do not manually delete ownership rows: they are the deletion safety
boundary. If a record is manually replaced, the controller logs an ownership
mismatch and refuses to mutate it; investigate and repair ownership
deliberately.

The shared hostname publishes at most `max_answers` healthy gateways, ordered
by lowest measured verification latency. Its TTL remains at Name.com's
300-second floor. Removing an answer therefore does not stop traffic
immediately: recursive resolvers, operating systems, and browsers may continue
using a withdrawn address for at least the cached TTL and sometimes longer.

## TLS enrollment

`POST /api/v1/gateways/reserve` solves the first-certificate ordering problem
without exposing DNS credentials. It authenticates the existing libp2p
identity, derives `gw-<sha256(node-id)[:24]>.syndichan.org`, and publishes a
short-lived A or AAAA record for the request's observed source address. The
client waits for that answer before starting exact-host HTTP-01 ACME. A
successful verified registration replaces the reservation; an abandoned one
expires after 15 minutes and is removed by reconciliation.

The controller never distributes wildcard private keys, ACME account
credentials, or Name.com credentials. A client cannot choose its hostname or
claim another address.

## Scaling

The API and verification path are stateless apart from PostgreSQL/Redis and can
scale horizontally. Increase replicas behind the ingress, size the async
database pool for the aggregate replica count, and use Redis for global rate
limits. Verification creates an outbound TLS connection per registration and
per health pass; for thousands of gateways, process health checks in bounded
batches and stagger intervals before raising the default ceiling.
