# Distributed Container Service (DCS)

An optional capability of `syndichan-node` that lets peers run Docker
containers for one another over I2P. No coordinator, no registry server, no
Swarm, no Kubernetes.

This document is the design. Nothing here is implemented yet; §20 is the
milestone plan.

---

## 0. Scope and the one rule that shapes everything

DCS is **off by default**. A node that has not set `dcs.enabled` participates in
nothing described here — it does not advertise, does not accept work, and does
not install a Docker client. Enabling it is an explicit act of donating compute
to strangers, and the design treats every request as hostile.

**Containers are addressed by I2P destination, never by IP.** Each container
gets its own SAM session and therefore its own `.b32.i2p`. A container's
identity on the network *is* that destination. Nothing in DCS transmits, logs,
or resolves a worker's clearnet address, and a container cannot learn the host's
address either (§10.4). This is the single constraint that most shapes the
networking design.

### What is reused, not rebuilt

DCS adds one protocol and four DHT namespaces. Everything else already exists:

| Need | Existing component | Reused how |
| --- | --- | --- |
| Peer identity | `gateway.Signer` (Ed25519, `12D3Koo…`) | Signs every DCS message; worker identity == node identity |
| Transport | `internal/i2p` SAM v3 + libp2p | New stream protocol on the same host |
| Discovery | `internal/p2p` Kademlia DHT | New namespaces, same `PutValue`/`GetValue` |
| Record validation | `gateway.DHTValidator` pattern | Same `Validate`/`Select`-by-sequence shape |
| Content addressing | `internal/store` (SHA-256, chunked, Reed-Solomon) | Image layers are blobs in the same store |
| Provider announce | `node.Provide` / `FetchShard` | Layer availability |
| Public exposure | `internal/gateway` frontend | Gateway Workers only (§10.6) |
| Presence | `internal/heartbeat` | Adds a `dcs` block → yellow on the map (§18) |

If a section below seems to invent something that already exists, that is a bug
in the design, not a feature.

---

## 1. Components

```
                    ┌──────────────────────────────────────────┐
   p2pctl ────────► │            DCS Manager (client side)     │
                    │  intent → plan → negotiate → reconcile   │
                    └───────┬──────────────────────────┬───────┘
                            │ RPC over I2P             │ DHT
                            ▼                          ▼
   ┌────────────────────────────────────┐   ┌────────────────────────┐
   │        Local Agent (worker)        │   │  DHT namespaces        │
   │ ┌────────────┐  ┌───────────────┐  │   │  worker / image /      │
   │ │ Secure RPC │──│ Authorizer    │  │   │  service / deployment  │
   │ └─────┬──────┘  └───────────────┘  │   └────────────────────────┘
   │       ▼                            │
   │ ┌────────────┐  ┌───────────────┐  │
   │ │ Runtime    │  │ Health Mon.   │  │
   │ │ (Docker API)│ │ Resource Mon. │  │
   │ └─────┬──────┘  └───────────────┘  │
   │       ▼                            │
   │ ┌────────────┐  ┌───────────────┐  │
   │ │ Image Store│  │ Task DB       │  │
   │ │ (CAS)      │  │ (bbolt)       │  │
   │ └────────────┘  └───────────────┘  │
   └────────────────────────────────────┘
```

**DCS Manager** — runs on the *deployer's* node, not on workers. Turns a user
intent ("3 replicas of nginx, GPU not required") into a plan, negotiates with
candidate workers, and owns the reconciliation loop for deployments it created.
There is one Manager per deployment owner; there is no global Manager.

**Local Agent** — the worker-side daemon. The only component that talks to
Docker. Accepts signed RPCs, enforces authorization and resource limits, and
publishes capability records. Refuses anything it did not authorize.

**Scheduler** — a *library*, not a service (§4). Runs inside the Manager. Scores
worker records from the DHT and produces a ranked candidate list. Two Managers
scheduling simultaneously may pick the same worker; the worker's admission
control resolves that (§4.4), not a lock.

**Registry** — decentralized image index in the DHT (§6). Maps human names to
digests, carries signatures and reputation.

**Runtime** — thin adapter over the Docker Engine API (`/var/run/docker.sock`)
with a hardened default profile (§9.5). The only place in DCS that knows Docker
exists, so a future podman backend is one interface implementation.

**Health Monitor** — per-container state machine on the worker (§11).

**Resource Monitor** — samples host CPU/RAM/disk/GPU, feeds both admission
control and the capability record.

**Task Database** — local bbolt store: deployments, container records,
operation journal, idempotency keys, secret ciphertexts. Authoritative for the
worker's own state; the DHT is a cache of it.

**Image Distribution** — layer-level content-addressed transfer over the
existing shard machinery (§5).

**Secure RPC Layer** — framed, signed, replay-protected request/response and
streaming over libp2p streams (§14).

---

## 2. Peer roles

Roles are **capability flags on one record**, not separate node types. A node
can be several at once.

| Role | Flag | Meaning |
| --- | --- | --- |
| Standard | *(none)* | DHT only. Never contacted by DCS. |
| Worker | `worker` | Accepts deployments. |
| Gateway Worker | `worker`,`gateway` | Also publishes container ports through the existing gateway frontend. Requires an already-verified gateway (§10.6). |
| Storage Worker | `worker`,`volumes` | Offers persistent volumes; advertises free bytes and IOPS class. |
| GPU Worker | `worker`,`gpu` | NVIDIA runtime present; advertises device model, VRAM, CUDA version. |

Role is *claimed* in the record and *proven* on use: a scheduler that needs GPU
sends a probe RPC that runs `nvidia-smi -L` inside a throwaway container before
committing a workload. Claims are cheap; proof happens at admission.

### 2.1 The bridge role (deploying for many users)

A **worker** runs containers; a **deployer** asks it to. The CLI (`-dcs-deploy`)
is a deployer for one person. A **bridge** is a deployer for *many* — a website
whose users cannot each run a node. It is a normal storage node with a loopback
HTTP API (`dcs.api_listen`, see the README) that a co-located site backend calls
to publish images, deploy, poll, and destroy.

The bridge holds one node identity but deploys for thousands of users, so each
deploy carries an opaque **`on_behalf_of`** sub-owner tag. The worker's
one-container-per-owner admission rule (§4.4) keys on that tag rather than on the
bridge's node id — otherwise a whole site collapses to one container per worker.
A worker only honours sub-accounting from a node it lists in
`policy.trusted_brokers`; from any other node, `on_behalf_of` is ignored and the
deployer is accounted as a single owner. This is the same trust a company places
in one service account that deploys for its employees: the *worker operator*
chooses which brokers may name their own sub-owners, so a stranger cannot mint
sub-owners to dodge the per-user cap.

Destroy is owner-checked: only the node that deployed a container may tear it
down (§7). A bridge that deployed on behalf of user A can destroy A's container;
no other node can.

---

## 3. Capability advertisement

### 3.1 Record

DHT key: `/syndichan-dcs-worker/<node-id>`

```go
type WorkerRecord struct {
    RecordType   string   `json:"record_type"`   // "dcs_worker"
    NodeID       string   `json:"node_id"`
    PublicKey    string   `json:"public_key"`    // base64, matches NodeID
    Destination  string   `json:"destination"`   // <b32>.i2p — how to reach the agent
    ProtocolVer  int      `json:"protocol_version"`
    AgentVersion string   `json:"agent_version"`

    Arch         string   `json:"arch"`          // linux/amd64
    DockerAPI    string   `json:"docker_api"`    // 1.45
    Capabilities []string `json:"capabilities"`  // worker,gpu,volumes,gateway,lab

    CPUCores     int      `json:"cpu_cores"`
    RAMBytes     int64    `json:"ram_bytes"`
    DiskBytes    int64    `json:"disk_bytes"`
    GPUs         []GPU    `json:"gpus,omitempty"`

    // Coarse buckets, never exact values. See 3.3.
    CPUFree      int      `json:"cpu_free_pct"`   // 0,10,…,100
    RAMFree      int      `json:"ram_free_pct"`
    DiskFree     int      `json:"disk_free_pct"`
    Slots        int      `json:"slots"`          // containers it will still accept
    Running      int      `json:"running"`

    Labels       map[string]string `json:"labels,omitempty"`
    Region       string   `json:"region,omitempty"`   // operator-declared, unverified
    HealthScore  int      `json:"health_score"`       // 0-100, see 3.4
    UptimeBucket string   `json:"uptime_bucket"`      // "<1h","1-24h","1-7d",">7d"

    Sequence     uint64   `json:"sequence"`
    IssuedAt     int64    `json:"issued_at"`
    ExpiresAt    int64    `json:"expires_at"`
    Signature    string   `json:"signature"`
}
```

### 3.2 Expiry and refresh

- **TTL 15 minutes** (`ExpiresAt = IssuedAt + 900`). A record whose `ExpiresAt`
  has passed is invalid — `WorkerValidator.Validate` rejects it, so expired
  workers vanish from scheduling without anyone deleting anything. This mirrors
  the gateway registration's expiry-not-deletion model, which already survives a
  hard crash correctly.
- **Republish every 5 minutes**, jittered ±60s. Three chances to refresh before
  expiry absorbs one missed DHT round trip and one restart.
- **Immediate republish** on any state change that would alter a scheduling
  decision: a slot filling or freeing, a capability appearing, health crossing a
  band boundary. Rate-limited to one per 30s so a flapping container cannot spam
  the DHT.
- **`Select` picks the highest `Sequence`**, identical to `gateway.DHTValidator`.
  `Sequence` is monotonic per node, persisted in the Task DB, so a restart never
  regresses and an old cached record can never win.

### 3.3 Why utilisation is bucketed

Exact `cpu_free = 37.2%` published every 5 minutes is a side channel: it
fingerprints the host and leaks when its human operator is using the machine.
Buckets of 10% are sufficient for scheduling and much weaker as a signal. The
same reasoning applies to `UptimeBucket` rather than exact uptime, and to
omitting hostname, kernel version and exact core model.

`Region` is operator-declared and **unverifiable** — it exists for latency
preference, and the scheduler treats it as a hint that costs nothing if false.
It is never a security boundary.

### 3.4 Health score

Locally computed, published, and independently distrusted:

```
health = 100
      − 30 × (crashloops_last_hour  / 5,  capped 1)
      − 20 × (oom_kills_last_hour   / 3,  capped 1)
      − 20 × (failed_admissions_1h  / 10, capped 1)
      − 15 × (i2p_tunnel_drops_1h   / 5,  capped 1)
      − 15 × (1 if disk_free < 10%)
```

A worker self-reports this, so it can lie. It is used only to *rank* — never to
authorize — and the deployer's own observed success rate (§4.5) overrides it.

---

## 4. Scheduling

### 4.1 The shape of the problem

There is no master, so scheduling is **client-side and speculative**. The
Manager reads a partial, stale view of the world from the DHT, picks candidates,
and *asks*. The worker is the authority on whether it will accept. This is
optimistic concurrency: no locks, no leases, no elected scheduler.

### 4.2 Algorithm

```
FILTER   — drop workers failing any hard constraint:
             expired record, protocol mismatch, missing capability,
             slots == 0, arch mismatch, anti-affinity violation,
             insufficient advertised RAM/disk, denylisted by owner
SCORE    — weighted sum over the survivors
SHORTLIST— take top K (default 5), shuffled within score bands
NEGOTIATE— sequential Reserve() until one accepts
```

Score:

```
score = w_res · resource_fit
      + w_hea · (health/100)
      + w_lat · latency_score
      + w_rel · observed_reliability
      + w_aff · affinity_match
      − w_pack · packing_penalty
```

`resource_fit` is **best-fit, not first-fit**: prefer the worker where the
container fits most snugly, so large workloads still have somewhere to go later.
`packing_penalty` rises as a worker approaches full, which spreads load without
needing a global view.

**Shuffling within score bands is load-bearing.** If every Manager scored
deterministically from the same DHT data, they would all pick the same "best"
worker simultaneously and thundering-herd it. Randomising within a band
decorrelates independent schedulers — the decentralised equivalent of the
power-of-two-choices trick.

### 4.3 Policies

| Policy | Implementation |
| --- | --- |
| Random | uniform over filtered set |
| Least loaded | maximise `min(cpu_free, ram_free)` |
| Most RAM | maximise `ram_free_pct × ram_bytes` |
| GPU required | hard filter + `nvidia-smi` probe at admission |
| Affinity | `labels ⊇ required` |
| Anti-affinity | reject workers already running a replica of the same deployment |
| Geographic | bonus for matching `region`, never a filter |
| Manual | single-element candidate list; skips scoring entirely |
| Priority | `priority_class` in `Reserve`; worker may preempt lower-class containers |
| Queueing | on total failure, retry with backoff (§4.6) |

### 4.4 Admission control resolves races

Two Managers may `Reserve` the same slot within milliseconds. The worker
serialises admission under a local mutex:

```
Reserve(spec):
  lock
  if slots_free == 0                      → REJECT(no_capacity)
  if cpu_committed + spec.cpu   > cpu_total  → REJECT(no_capacity)
  if ram_committed + spec.ram   > ram_total  → REJECT(no_capacity)
  if !authorized(spec.owner, "deploy")       → REJECT(forbidden)
  if !policy_allows(spec.image)              → REJECT(policy)
  reservation = {id, spec, expires: now+120s}
  commit resources; slots_free--
  unlock
  return ACCEPT(reservation_id, ttl)
```

Reservations **expire in 120 seconds** if not claimed by a `Launch`. Without
that, a Manager that crashes between `Reserve` and `Launch` permanently leaks
the worker's capacity — and since no coordinator exists to notice, that leak
would be unrecoverable without an operator restart.

### 4.5 Observed reliability beats advertised health

Each Manager keeps a local, private EWMA per worker:

```
reliability ← 0.9·reliability + 0.1·(1 if deployment reached Running else 0)
```

This is the deployer's own experience, cannot be forged by the worker, and
naturally routes around nodes that advertise well and perform badly. It is never
published — publishing it would create a reputation system with all the sybil
and griefing problems that implies.

### 4.6 Queueing

Failure to place is not an error; it is backpressure. The deployment enters
`Pending` and retries with exponential backoff (30s → 15min, jittered),
refreshing the DHT view each attempt. `p2pctl ps` shows `Pending (no worker
matched: gpu=true, 0 of 4 candidates)` — the reason, not just the state.

---

## 5. Image distribution

### 5.1 Docker layers are already content-addressed

A Docker image is a manifest plus layer blobs, each named by its own SHA-256.
That is exactly what `internal/store` already stores, verifies and replicates.
DCS does not build a new CAS; it registers layer blobs in the existing one.

```
image manifest (sha256:abcd…)
   ├── layer sha256:1111…  ─┐
   ├── layer sha256:2222…   ├─→ store.Put() → chunked, encrypted,
   └── config sha256:3333… ─┘        Reed-Solomon, Provide()d to the DHT
```

Deduplication is free and global: two images sharing a Debian base share the
blob, and a worker that already has it transfers nothing.

### 5.2 Pull path

```
Manager                          Worker                       Network
   │ Launch(manifest_digest)       │
   ├──────────────────────────────►│
   │                               │ have manifest? ──no──► FindProviders(digest)
   │                               │                        FetchShard × N
   │                               │ verify sha256 ← REQUIRED
   │                               │ for each layer:
   │                               │   have? ──yes──► skip        (dedup)
   │                               │   no ──► FindProviders → fetch → verify
   │                               │ docker load
   │◄──── LayerProgress stream ────┤
```

Every blob is verified against its digest **before** it reaches Docker. A layer
that fails verification is discarded, the provider is scored down locally, and
the fetch retries elsewhere. This is the same discipline the shard store already
applies, and it is why a hostile provider cannot inject a modified layer.

### 5.3 Torrent-like fetch

Layers are chunked by the existing store. A worker fetches chunks from multiple
providers in parallel, rarest-first, and re-`Provide`s each chunk as it lands —
so popular base images naturally gain replicas as they are deployed. Cold-start
for a genuinely novel image is one round trip to whoever published it.

### 5.4 Garbage collection

Layers are refcounted by the containers referencing them. A layer with zero refs
enters a grace period (default 7 days) before deletion, because the same base
image is very likely to be requested again. GC is bounded by
`dcs.image_cache_bytes`; when over budget it evicts by
`(refcount == 0, last_used ASC, size DESC)`.

**Cache poisoning is not possible** — content addressing means a corrupted blob
simply fails its digest check and is refetched. Corruption is a liveness
problem, never a correctness one.

---

## 6. Image registry

DHT key: `/syndichan-dcs-image/<sha256-of-canonical-name>`

```go
type ImageRecord struct {
    RecordType string   `json:"record_type"`  // "dcs_image"
    Name       string   `json:"name"`         // "nginx"
    Tag        string   `json:"tag"`          // "1.27"
    Digest     string   `json:"digest"`       // sha256:… of the manifest
    Arch       []string `json:"arch"`
    SizeBytes  int64    `json:"size_bytes"`
    Layers     []string `json:"layers"`
    Author     string   `json:"author"`       // publisher node ID
    PublicKey  string   `json:"public_key"`
    Signature  string   `json:"signature"`    // over everything above
    Sequence   uint64   `json:"sequence"`
    IssuedAt   int64    `json:"issued_at"`
    ExpiresAt  int64    `json:"expires_at"`   // 30 days
}
```

### 6.1 Names are not global

`nginx` published by two people is two records under two keys, because the key
includes the publisher: the canonical name is `<author-node-id>/<name>:<tag>`.
There is no global namespace to squat, no first-come-first-served land grab, and
no need for a naming authority. `p2pctl` resolves a bare `nginx` only if the
user has that publisher in their trust list or pins the digest.

**Digest beats name, always.** A deployment spec records the digest it resolved;
re-deploying uses the digest, so a publisher cannot swap content under a tag
after the fact.

### 6.2 Reputation

Deliberately *not* a network-wide score. Each node keeps a local trust list
(pinned publisher keys) plus counts of successful pulls. A global reputation
number would be the single most attackable part of the system and the least
useful.

---

## 7. Deployment lifecycle

```
p2pctl deploy nginx --replicas 3
   │
   ▼
[1] Resolve image ──── DHT GetValue(/syndichan-dcs-image/…) ──► digest + layers
   │
[2] Build DeploymentSpec, sign it, assign deployment ID
   │
[3] Scheduler: read /syndichan-dcs-worker/* → filter → score → shortlist
   │
[4] for each replica:
   │      Reserve(spec)          ──RPC──►  worker   ──► ACCEPT(reservation, ttl)
   │      Launch(reservation)    ──RPC──►  worker
   │                                       ├ pull layers (§5.2)
   │                                       ├ create I2P destination for container
   │                                       ├ docker create + start
   │                                       └ health probe until Running
   │      ◄── LaunchResult(container_id, i2p_destination) ───
   │
[5] Publish /syndichan-dcs-deploy/<deployment-id>   (owner-signed)
   │
[6] Publish /syndichan-dcs-service/<owner>/<service> (if service ports declared)
   │
[7] Manager enters reconciliation loop (§13)
   │
   ▼
deployment ID: dcs-01HQ…-nginx
```

Messages, in order: `Reserve` → `ReserveAck` → `Launch` → `LayerProgress*` →
`LaunchResult` → (`StatusUpdate*` for the life of the container).

**Idempotency.** Every mutating RPC carries a client-generated
`operation_id` (UUIDv7). The worker journals it in the Task DB before acting and
returns the recorded result on replay. A Manager that times out and retries
therefore cannot double-launch, which matters because I2P round trips are slow
and timeouts are common.

---

## 8. Remote management RPCs

One protocol: `/syndichan/dcs/1.0.0`. All operations are request/response except
the four streaming ones.

| RPC | Streams | Notes |
| --- | --- | --- |
| `Reserve` / `Release` | | admission control |
| `Launch` | ← progress | |
| `Start` `Stop` `Restart` `Pause` `Resume` `Kill` | | `Stop` takes a grace period |
| `Destroy` | | releases volumes per policy |
| `Rename` `Relabel` | | metadata only |
| `UpdateImage` | ← progress | §15 |
| `Inspect` | | redacted (§8.1) |
| `Logs` | ← stream | §9 |
| `Exec` | ↔ bidi | §8.2 |
| `PutFile` / `GetFile` | ↔ chunked | resumable, digest-verified |
| `SetEnv` `SetPorts` `SetVolumes` `SetNetwork` | | requires restart; returns `restart_required` |
| `PutSecret` / `RotateSecret` / `RevokeSecret` | | §17 |
| `Snapshot` / `Restore` | ← progress | volume-level (§10.3) |
| `Metrics` | ← stream | §10 |
| `Probe` | | capability proof (GPU, arch) |

### 8.1 Inspect is redacted

`docker inspect` output contains the host's mount paths, hostname, and network
configuration. The agent returns a **whitelisted projection** — container state,
image digest, declared ports, resource limits, health — never the raw Docker
response. Anything not on the whitelist is absent, so a future Docker version
adding a new field cannot leak it by default.

### 8.2 Remote shell

`Exec` is the most dangerous RPC in the system and is treated accordingly:

- separate permission (`shell`), never implied by `deploy` or `admin`
- **off unless the worker sets `dcs.allow_exec`** — a worker can host containers
  while refusing interactive access entirely
- always inside the target container's namespaces, never on the host
- every session start/end is audit-logged with the requester's node ID
- session-scoped: a bidi stream, no persistent daemon, dies with the stream
- optional `dcs.exec_recording` writes a transcript the *worker's* operator can
  read — they are lending their hardware and are entitled to know what ran

---

## 9. Logs

Transport: a libp2p stream over I2P carrying length-prefixed frames.

```
LogRequest{container, follow, since, until, tail_lines, filter, level, compress}
   → LogFrame{seq, ts_unix_nano, stream(stdout|stderr), data}  ×N
   → LogEnd{reason, dropped_count}
```

- **Historical**: agent reads the Docker JSON log file, seeks by timestamp.
- **Streaming**: attaches to the Docker log stream; frames forwarded live.
- **Search/filter**: applied *at the worker* — this matters, because sending a
  gigabyte over I2P so the client can grep it would be absurd. Substring and
  RE2 (never backtracking regex — a hostile pattern must not be able to pin the
  worker's CPU).
- **Compression**: zstd per batch when a batch exceeds 4 KiB. I2P bandwidth is
  the scarce resource here; CPU is not.
- **Backpressure**: a bounded ring buffer per stream. A slow reader causes
  *dropping*, not unbounded memory growth, and `LogEnd.dropped_count` reports
  exactly how many frames were lost. Silent truncation would be worse than a
  gap.

---

## 10. Metrics

```
MetricsRequest{containers[], interval_seconds, fields[]}
   → MetricsFrame{ts, container_id, cpu_pct, mem_bytes, mem_limit,
                  net_rx, net_tx, blk_read, blk_write, restarts,
                  health, uptime_s, gpu_util, gpu_mem, temp_c}  ×N
```

Sampled from the Docker stats API plus `nvidia-smi` where present. Minimum
interval **5 seconds** — anything faster costs more in I2P overhead than the
data is worth. Frames are deltas after the first full frame; the client
reconstructs. A dropped frame is detectable via the sequence number and
triggers a full frame on the next tick.

---

## 11. Health monitoring

Per-container state machine on the worker:

```
        ┌────────┐  start   ┌──────────┐  probe ok   ┌─────────┐
        │Created ├─────────►│ Starting ├────────────►│ Running │
        └────────┘          └────┬─────┘             └────┬────┘
                                 │ probe fail ×N          │ exit
                                 ▼                        ▼
                            ┌──────────┐            ┌──────────┐
                            │ Unhealthy│◄───────────┤ Exited   │
                            └────┬─────┘  restart   └────┬─────┘
                                 │ policy exhausted      │
                                 ▼                       ▼
                            ┌──────────────────────────────┐
                            │        CrashLooping          │
                            └──────────────────────────────┘
```

Detection:

| Condition | Signal |
| --- | --- |
| Crash loop | ≥5 exits in 10 min → `CrashLooping`, stop restarting |
| OOM kill | `State.OOMKilled` from Docker |
| High CPU/RAM | sustained >95% of limit for 5 min |
| Deadlock | health check times out while process still alive |
| Network failure | container's I2P tunnel down >2 min |
| Disk exhaustion | host free <5% → refuse new work, alert owner |
| Health check | Docker `HEALTHCHECK` or DCS-configured HTTP/TCP/exec probe |

**Restart backoff is exponential with a cap** (1s, 2s, 4s … 300s) and the
counter resets after 10 minutes of stability. A tight restart loop on a
volunteer's machine is a resource-exhaustion attack — capped backoff plus the
`CrashLooping` terminal state means a broken container costs the host a bounded
amount of work, and the owner is told rather than the container being restarted
forever.

---

## 12. Persistent volumes

| Mode | Guarantee | Cost |
| --- | --- | --- |
| `local` | Docker named volume on that worker | Fast. Dies with the worker. |
| `replicated` | Snapshot to the shard store on a schedule | Recovery to last snapshot; RPO = snapshot interval |
| `distributed` | Every write erasure-coded into the shard store | Survives worker loss; write latency over I2P is brutal |

**The honest tradeoff:** `distributed` is correct and slow. An I2P round trip is
tens of seconds under load, so synchronous distributed writes are unusable for
anything database-shaped. Default is `local`; `replicated` is the recommended
middle; `distributed` exists for small, write-rare, loss-intolerant data.

Volumes are encrypted at rest with a key derived from the **owner's** identity,
not the worker's — so a worker operator cannot read the data they are storing,
and a migrated volume remains readable by its owner alone.

Migration: snapshot → transfer → verify digest → mount on new worker → destroy
old only after the new one reports healthy. The old copy is never deleted before
the new one is proven, because a half-migrated volume with both copies gone is
unrecoverable.

---

## 13. Networking

### 13.1 One destination per container

At launch the agent opens a **new SAM session** for the container, producing a
fresh `.b32.i2p`. That destination is the container's address, everywhere:
service records, DNS, load balancing, logs. The worker's own destination is
never used for container traffic, so container-to-container flows do not reveal
which containers are co-located.

### 13.2 Overlay

```
container ──veth──► worker netns ──SAM──► container's own I2P destination
                          │
                          └── egress policy (default: DENY ALL)
```

Containers get **no clearnet egress by default**. A container that needs the
internet must be granted `net.clearnet` explicitly by the *worker's* operator,
not by the deployer — otherwise DCS becomes an open proxy and every volunteer an
unwitting exit node.

### 13.3 Internal DNS

The agent runs a resolver on the container's gateway address, serving a
synthetic zone:

```
<container-alias>.<deployment>.dcs   →  <b32>.i2p
<service>.<owner>.svc.dcs            →  round-robin over healthy replicas
```

Resolution is a DHT lookup of the service record, cached for the record's TTL.
No global DNS, no external resolver, no leak.

### 13.4 Load balancing

Client-side. The resolver returns healthy replicas shuffled, weighted by
observed latency. There is no load balancer process to be a single point of
failure — which is fortunate, since there is nowhere central to run one.

### 13.5 Gateway publication

Only a **Gateway Worker** with an already-verified gateway registration may
expose a container publicly. The existing SNI frontend routes a hostname to the
container's local port. This deliberately reuses §Gateway's verification: a node
must already have proven public reachability through probe quorum or controller
connect-back before it can publish anything.

---

## 14. Security

### 14.1 Every request is signed

```
Envelope{
  version, operation_id, from_node, to_node,
  issued_at, expires_at (≤120s), nonce,
  payload, signature
}
```

Worker verifies, in this order: protocol version → `to_node == self` (an
envelope for another node is never executed) → freshness → nonce unseen →
signature → authorization. Nonces are kept for `2 × max_skew`; the short expiry
bounds that table.

Transport encryption is libp2p Noise over I2P, already in place. The envelope
signature is *additional* — it authenticates the request itself, so a
compromised transport cannot forge an operation and the audit log entry is
independently verifiable.

### 14.2 Authorization model

Capability grants, not roles. Owners issue signed, expiring grants:

```go
type Grant struct {
    Issuer, Subject string   // node IDs
    Scope           string   // deployment ID, or "*" for all of issuer's
    Permissions     []string // deploy,destroy,restart,logs,shell,files,
                             // publish_images,schedule,admin,read
    NotBefore, NotAfter int64
    Signature       string
}
```

- The **worker operator's** local policy is checked first and always wins. A
  grant cannot make a worker do something its operator disallowed —
  `dcs.allow_exec=false` beats any `shell` grant that exists.
- Grants are presented with the request, not looked up — no revocation-list
  round trip on the hot path. Revocation is handled by short lifetimes (default
  24h) plus an explicit revocation record in the DHT checked on refresh.
- `admin` never implies `shell`. They are separately grantable because they are
  separately dangerous.

### 14.3 Container sandboxing defaults

Applied to every container unless the worker's operator explicitly relaxes them:

```
--cap-drop=ALL                    --security-opt=no-new-privileges
--read-only (writable via tmpfs / declared volumes only)
--pids-limit, --memory, --cpus, --ulimit nofile
seccomp: docker default           apparmor: docker-default
no --privileged, no --pid=host, no --network=host,
no docker.sock mount, no device passthrough except declared GPUs
user namespace remapping where the daemon supports it
```

**Refused unconditionally**, regardless of grants: `--privileged`,
`/var/run/docker.sock` mounts, host PID/network namespace, arbitrary device
mounts. A worker that allowed any of these would be handing root on its own
machine to a stranger, and no permission system makes that acceptable.

### 14.4 Audit log

Append-only, local, signed per entry. Records the requester, operation,
container, decision and reason. It is the worker operator's record of what
strangers did with their hardware — deliberately not transmitted anywhere.

---

## 15. Replication and rolling updates

### 15.1 Reconciliation

Owner-side loop, every 60s ± jitter:

```
observe: for each replica → StatusRequest (or mark Unknown on timeout)
diff:    desired − healthy
act:     healthy < desired → schedule the difference
         healthy > desired → Destroy the newest surplus first
         Unknown > threshold → wait one more interval before acting
```

The `Unknown` grace period is what stops a **network partition from causing
replica storms**. If a partition makes 3 healthy replicas look dead, acting
immediately would launch 3 more; when the partition heals there are 6, and the
loop then destroys 3 — churning the whole time. Treat unreachable as unknown,
not dead, and require two consecutive intervals before replacing.

### 15.2 Update strategies

| Strategy | Behaviour |
| --- | --- |
| Rolling | one at a time: launch new → healthy → destroy old → next. `max_unavailable` configurable |
| Blue/green | full parallel set, atomic service-record switch, old set retained for `rollback_window` |
| Canary | 1 replica on the new digest, hold for `bake_time`, promote or roll back on metrics |
| Rollback | service record reverts to the previous digest; every deployment record keeps its predecessor |

Automatic rollback triggers on: health failure during bake, crash loop on the
new digest, or error-rate regression beyond threshold. Rollback targets a
**digest**, never a tag, so it is exact.

---

## 16. Failure recovery

| Failure | Detection | Recovery |
| --- | --- | --- |
| Worker disappears | record expires (15m) + RPC timeout | Unknown → 2 intervals → reschedule elsewhere |
| Container crashes | Docker event | restart policy w/ backoff, then `CrashLooping` |
| Power failure | agent restart | reconcile Task DB against live Docker state; adopt or clean up orphans |
| Network partition | RPC timeouts, DHT unreachable | freeze reconciliation, do **not** destroy, resume on heal |
| Image corruption | digest mismatch | discard, downrank provider, refetch |
| Disk full | resource monitor | refuse new work, GC image cache, alert owner |
| I2P tunnel loss | SAM session error | rebuild session, container keeps its destination key so its address survives |

**Split brain** is bounded by design: the worker is the sole authority on what it
is running. Two Managers cannot both believe they own a container, because
ownership is recorded in the container's own record on the worker, signed by the
owner at launch.

---

## 17. Secrets

Never in images, never in the DHT in plaintext, never in `docker inspect`.

```
owner encrypts secret to the worker's X25519 key (derived from its Ed25519 identity)
   → ciphertext travels in PutSecret
   → agent decrypts into tmpfs, mounts at /run/secrets/<name>
   → never written to disk, never in an image layer, never in an env var by default
```

Environment variables are supported but **discouraged in the CLI output**,
because env leaks through `docker inspect`, crash dumps and child processes.
File mounts are the default.

Rotation writes a new version; the container sees an atomic symlink swap and
either re-reads or is restarted per policy. Revocation deletes the tmpfs copy
and restarts. Versions are retained so a rollback has its matching secret.

---

## 18. World map integration (yellow)

The map already colours storage blue, gateway green, visitor red, driven by the
five-minute heartbeat. DCS adds one block:

```json
"dcs": { "enabled": true, "worker": true, "gpu": false,
         "slots": 4, "running": 2, "agent_version": "1.0.0" }
```

- `backend/services/storage_coordination.py` — validate the block; absent means
  not participating (must not fail an existing storage-only heartbeat).
- `backend/model/StorageNode.py` — add `dcs_enabled`, `dcs_worker`, `dcs_slots`,
  `dcs_running`; expose `"container": bool(node.dcs_enabled)` in the map row
  alongside the existing `storage` / `gateway` keys.
- Map renderer — `container` → **yellow**. A node with several roles already
  draws an alternating dot, so yellow composes with blue/green/red for free.

Capacity `0` already means "not a storage node" (fixed earlier this session), so
a DCS-only node with no donated disk renders correctly as yellow alone.

---

## 19. Management page and Attack Range

### 19.1 Management UI

Lives in the existing site, not in the node: `/containers` for owners,
`/admin/containers` for operators. Jinja + Bootstrap 4 on the `--sc-*` palette,
so it follows the theme selector like every other page.

The website is **not** a coordinator. It is a client that speaks to the user's
own node, and it shows only what that node can see. Making it authoritative
would reintroduce exactly the centralisation this design exists to avoid.

### 19.2 Attack Range — read this before wiring it up

`splunk/attack_range` builds **deliberately vulnerable** hosts to generate
attack telemetry. It is legitimate, widely used security-research tooling, and
it is a genuinely good fit for the "spin up a lab on demand" shape of DCS.

It is also the single most dangerous thing you could schedule onto other
people's machines, and the design has to say so plainly:

1. **It is not a normal workload.** Deploying knowingly-exploitable services
   onto a volunteer's hardware, reachable over an anonymity network, creates
   real risk for someone who did not read the manifest.
2. **Separate opt-in.** A `lab` capability, distinct from `worker`. A worker
   advertising `worker` must never receive lab workloads. Opting in should
   require an explicit config flag whose comment says exactly what it means.
3. **Never gateway-published.** A lab container must not be exposable through
   the public gateway. This is a hard refusal in the agent, not a policy knob.
4. **Egress denied, no exception.** §13.2's default deny is mandatory for lab
   containers — no `net.clearnet` grant is honoured. A vulnerable box that can
   reach the internet is a launch platform.
5. **Reachable only by the owner's destination.** The container's I2P
   destination is shared with the deploying owner alone, never in a public
   service record.
6. **Hard TTL.** Lab deployments carry a mandatory `max_runtime` (default 4h)
   after which the agent destroys them regardless of owner state. A forgotten
   vulnerable container is the failure mode to design against.
7. **Prominent attribution in the UI.** The management page must show what a lab
   deployment is, on the worker's own dashboard, so an operator can see they are
   hosting one.

With those in place the integration itself is small: Attack Range's per-role
containers become DCS deployment specs, its Splunk indexer is one more
container, and the range's internal addressing uses `.dcs` names (§13.3) rather
than the IPs its Terraform/Ansible paths assume. That last part is the bulk of
the real work — Attack Range assumes routable IPv4 in many places.

---

## 20. Roadmap

Each milestone is independently testable and leaves the node shippable.

| # | Milestone | Done when |
| --- | --- | --- |
| 1 | **Config + capability record** — `dcs.enabled`, `WorkerRecord`, validator, publish/expire | Two nodes see each other's records; expiry removes them; role validation refuses a storage-only config |
| 2 | **Secure RPC** — envelope, signing, replay, versioning, `Ping`/`Probe` | Signed round trip over I2P; replayed envelope rejected; wrong `to_node` rejected |
| 3 | **Docker runtime adapter** — hardened create/start/stop/destroy, no network yet | Container runs locally with the §14.3 profile; `--privileged` refused |
| 4 | **Reserve/Launch + Task DB** — admission, reservations, idempotency journal | Concurrent Reserves race safely; duplicate `operation_id` returns the first result |
| 5 | **Image distribution** — layers into the shard store, digest-verified pull | Cold pull works; second worker dedups shared layers; corrupted layer refetches |
| 6 | **Scheduler** — filter/score/shortlist, all policies | Placement across 3 workers; anti-affinity honoured; no worker starves |
| 7 | **Per-container I2P** — SAM session per container, destination in the record | Two containers reach each other by `.b32.i2p`; no clearnet egress |
| 8 | **Health + restart policy** | Crash loop terminates in `CrashLooping`; OOM detected; backoff observed |
| 9 | **Logs + metrics streaming** | Tail, follow, filter, backpressure drop counted |
| 10 | **Replication + reconciliation** | Kill a worker → replica reappears; partition → no storm |
| 11 | **Exec + file transfer** | Interactive shell; resumable upload; refused when `allow_exec=false` |
| 12 | **Secrets + volumes** | Sealed secret in tmpfs; volume snapshot/restore/migrate |
| 13 | **Service discovery + DNS + gateway publication** | `svc.dcs` resolves and load-balances; only verified gateways publish |
| 14 | **Rolling/canary/rollback** | Canary auto-rolls-back on induced failure |
| 15 | **Heartbeat + yellow on the map** | DCS node renders yellow; storage-only unaffected |
| 16 | **Management page** | Deploy/inspect/logs from the site against the user's own node |
| 17 | **Attack Range** | Lab capability, TTL enforced, egress denied, `.dcs` addressing |

Milestones 1–5 are the foundation and should not be reordered: everything above
depends on records, signed RPC and content-addressed images existing first.

---

## 21. Configuration

```json
{
  "dcs": {
    "enabled": false,
    "role": { "worker": false, "gpu": false, "volumes": false, "lab": false },
    "limits": {
      "max_containers": 8,
      "cpu_share_pct": 50,
      "ram_bytes": 4294967296,
      "disk_bytes": 53687091200,
      "image_cache_bytes": 21474836480,
      "bandwidth_kbps": 0,
      "max_runtime_seconds": 0
    },
    "policy": {
      "allow_exec": false,
      "exec_recording": false,
      "allow_clearnet_egress": false,
      "allow_gateway_publish": false,
      "image_allowlist": [],
      "trusted_publishers": [],
      "owner_allowlist": []
    },
    "labels": {},
    "region": "",
    "docker_endpoint": "unix:///var/run/docker.sock",
    "advertise_interval_seconds": 300,
    "record_ttl_seconds": 900
  }
}
```

Every default is the safe one: disabled, no exec, no egress, no publishing,
empty allowlists. Turning DCS on gets you a node that advertises nothing until
you also pick a role.
