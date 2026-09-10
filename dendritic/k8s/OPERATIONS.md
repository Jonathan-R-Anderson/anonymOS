# Starting and stopping the stack

Covers both stacks, because during the migration **both exist at once**: the live
compose stack keeps serving traffic while the k3s cluster is validated alongside it.

- Software node — `syndichan.org` (51.79.71.153) — app tier, edge, aggregators, media
- Data node — `node.syndichan.org` (148.113.203.46) — postgres and redis

Every command below is run as `ubuntu` over SSH and needs `sudo`.

---

## 1. The compose stack (what serves the site today)

```bash
cd ~/maniwani
```

| action | command |
|---|---|
| start everything | `sudo docker compose up -d` |
| stop everything, keep containers | `sudo docker compose stop` |
| stop and remove containers (volumes survive) | `sudo docker compose down` |
| restart one service | `sudo docker compose restart maniwani` |
| rebuild + restart one service | `sudo docker compose build maniwani && sudo docker compose up -d maniwani` |
| follow logs | `sudo docker compose logs -f --tail=200 maniwani` |
| what is running | `sudo docker compose ps` |

**`down` never deletes data.** The 14 named volumes are separate objects. Only
`docker compose down -v` destroys them — do not run that.

### The 80-second boot window

Every `up`/rebuild leaves the site returning nginx's "starting up" 503 for roughly
80 seconds while uwsgi imports the app. This is normal and self-clears. It is the
usual cause of a "the site is down after deploy" report.

Confirm it is the boot window and not a real failure:

```bash
sudo docker inspect maniwani-maniwani-1 --format '{{.RestartCount}}'   # expect 0
sudo docker compose logs nginx | grep ' 502 ' | tail             # all clustered in one minute
```

---

## 2. The k3s stack (after migration)

k3s itself is two systemd units — the server on the software node, the agent on the
data node. Stopping a unit stops that node's workloads; it does not delete anything.

### The cluster daemons

```bash
# software node (control plane + app tier)
sudo systemctl status k3s
sudo systemctl stop k3s
sudo systemctl start k3s

# data node (postgres / redis)
sudo systemctl status k3s-agent
sudo systemctl stop k3s-agent
sudo systemctl start k3s-agent
```

Stopping `k3s-agent` on the data node takes the database with it — the app tier will
fail its probes and restart-loop until the agent is back. Stop the app tier first if
the outage is planned (see below).

### The workloads

`kubectl` is on the software node; k3s writes its kubeconfig to
`/etc/rancher/k3s/k3s.yaml`, so either use `sudo` or export it:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

**Stop the application, leave the cluster and data running** — the normal "shut the
site down" operation. Order matters: drop the app tier before the data tier so the
backend is not writing while postgres goes away.

```bash
kubectl -n maniwani scale deployment,statefulset --replicas=0 \
  -l maniwani.io/group=app
kubectl -n maniwani scale deployment,statefulset --replicas=0 \
  -l maniwani.io/group=aggregators
kubectl -n maniwani scale deployment,statefulset --replicas=0 \
  -l maniwani.io/group=media
kubectl -n maniwani scale statefulset/syndichan-node --replicas=0
kubectl -n maniwani scale deployment,statefulset --replicas=0 \
  -l maniwani.io/group=data          # optional; only if you want the DB down too
```

**Start it again** — reverse order, data first, and wait for it to be ready before
the app tier comes back or the backend will crash-loop on connection refused:

```bash
kubectl -n maniwani scale statefulset postgres --replicas=1
kubectl -n maniwani scale deployment redis --replicas=1
kubectl -n maniwani rollout status statefulset/postgres --timeout=300s
kubectl -n maniwani scale statefulset syndichan-node --replicas=1
kubectl -n maniwani rollout status statefulset/syndichan-node --timeout=600s

kubectl -n maniwani scale deployment,statefulset --replicas=1 -l maniwani.io/group=app
kubectl -n maniwani scale deployment,statefulset --replicas=1 -l maniwani.io/group=media
kubectl -n maniwani scale deployment,statefulset --replicas=1 -l maniwani.io/group=aggregators
```

Scaling to 0 is preferred over `kubectl delete`: it keeps Services, PVCs, Secrets and
NetworkPolicies in place, so starting back up is one command and nothing needs
re-applying.

### Everyday checks

```bash
kubectl -n maniwani get pods -o wide                    # which node each pod landed on
kubectl -n maniwani get pvc                             # bound? and to which class
kubectl -n maniwani logs -f deploy/maniwani --tail=200
kubectl -n maniwani rollout restart deployment/maniwani # restart without changing anything
kubectl -n maniwani describe pod <name>                 # why a pod is Pending
```

A pod stuck **Pending** is almost always placement: its PVC's storage class and its
`nodeSelector` disagree, so no node can satisfy both. That failure is deliberate — it
is loud instead of silently landing the database on the wrong machine.

---

## 3. Cutover and rollback

Both stacks run on the same software node behind the same public IP, so **only one can
hold :80/:443**. Until cutover, k3s nginx sits on 8080/8443 and the compose stack owns
the real ports. The switch is a port swap on one host, not a DNS change.

The edge is exposed with **hostPort**, not a NodePort or LoadBalancer — so the port
that matters lives on the Deployment's container ports, not on the Service. The
Service is deliberately `ClusterIP`; making it `type: LoadBalancer` would make k3s
ServiceLB spawn a `0.0.0.0` hostPort DaemonSet and fight for the same ports.

**Cut over to k3s** — replace the whole ports array, not just the hostPort values.

Pre-cutover the edge also carries `hostIP: 127.0.0.1`, which keeps it loopback-only
while the real site is live next door. That line **must go at cutover** — a patch that
only changes the port numbers leaves the edge bound to loopback, so :443 answers
locally and the public site stays dark. A JSON-patch `replace` on the whole array is
what removes it; a strategic-merge patch would *merge* by `containerPort` and silently
leave `hostIP` in place.

```bash
cd ~/maniwani
sudo docker compose stop nginx                       # release 80/443 first

kubectl -n maniwani patch deployment nginx --type=json -p '[
  {"op":"replace","path":"/spec/template/spec/containers/0/ports","value":[
    {"name":"http","containerPort":80,"protocol":"TCP","hostPort":80},
    {"name":"https","containerPort":443,"protocol":"TCP","hostPort":443}
  ]}
]'
kubectl -n maniwani rollout status deployment/nginx --timeout=120s

# Verify it is bound to 0.0.0.0 and not 127.0.0.1 before trusting it:
sudo ss -lntp | grep -E ':(80|443)\b'
curl -sS -o /dev/null -w '%{http_code}\n' https://syndichan.org/    # expect 200
```

The Deployment is `replicas: 1` with `strategy: Recreate` on purpose: a hostPort is a
node-exclusive resource, so a rolling update would deadlock waiting for the old pod to
release a port it only releases once terminated.

**Roll back to compose** — put the k3s edge back on its validation ports so it releases
80/443, then start compose nginx:

```bash
kubectl -n maniwani patch deployment nginx --type=json -p '[
  {"op":"replace","path":"/spec/template/spec/containers/0/ports","value":[
    {"name":"http","containerPort":80,"protocol":"TCP","hostPort":8081,"hostIP":"127.0.0.1"},
    {"name":"https","containerPort":443,"protocol":"TCP","hostPort":8443,"hostIP":"127.0.0.1"}
  ]}
]'
kubectl -n maniwani rollout status deployment/nginx --timeout=120s
sudo docker compose up -d nginx
```

If you need the site back *immediately* and do not care about the k3s edge, scaling it to
zero frees the ports in one step: `kubectl -n maniwani scale deploy/nginx --replicas=0`
followed by `sudo docker compose up -d nginx`.

Roll back the whole thing (compose was never stopped, only its nginx):

```bash
kubectl -n maniwani scale deployment,statefulset --replicas=0 --all
cd ~/maniwani && sudo docker compose up -d
```

Lower the DNS TTL to 60s a day beforehand as cheap insurance, even though this plan
does not change any A record.

---

## 4. Things that will bite

- **`docker compose down -v` destroys all 14 volumes.** Never use `-v` here.
- **The storage-node PVC is directory-backed.** Its request is not a quota; use
  the dashboard allocation and monitor both `/data/node` and host `df`.
- **Do not install k3s with `--disable-network-policy`.** Every NetworkPolicy silently
  becomes a no-op while still appearing in `kubectl get netpol`, which leaves postgres,
  redis and the storage gateway exposed inside the cluster.
- **Postgres credentials** are `dev/dev/dev` inline in compose and are *not* in `.env`.
  The `maniwani-env` Secret must carry `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB`
  or postgres will not start under k8s.
