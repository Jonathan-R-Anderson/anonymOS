# maniwani → k3s: bootstrap & cutover runbook

**Every command in this document is safe to run against the live site unless it sits under a
heading marked `[WINDOW]`.** The `[WINDOW]` steps are the only ones that interrupt traffic, and
they are collected in §11 so you can read them before you start.

This is an operator runbook, not a design document. The design lives in the header comments of
the manifests in `k8s/data`, `k8s/app`, `k8s/aggregators` and `k8s/media` — read the header of a
manifest before you change anything in it.

---

## 0. Ground truth

Measured on the live servers. Do not re-derive; if reality disagrees with this table, stop and
find out why before continuing.

| | SOFTWARE node | DATA node |
|---|---|---|
| hostname / k8s node name | `vps-8e766dc0` | `vps-56548ec0` |
| public DNS | `syndichan.org` | `node.syndichan.org` |
| public IP (ens3, /32) | `51.79.71.153` | `148.113.203.46` |
| WireGuard address (planned) | `10.99.0.1` | `10.99.0.2` |
| CPU / RAM | 8 vCPU / 22 GB | 4 vCPU / 7 GB |
| disk | 200 GB (97 G free) | 75 GB (55 G free) |
| swap | none | none |
| OS / kernel / cgroups | Ubuntu 26.04, 7.0.0, v2 | same |
| runs today | the entire compose stack | nothing |
| k3s role | server | agent |
| node label | `maniwani.io/role=software` | `maniwani.io/role=data` |
| storage class | `maniwani-local` | `maniwani-data` |

Verified prerequisites on **both** nodes: `CONFIG_WIREGUARD=m` and the module loads;
`br_netfilter`, `overlay`, `nf_conntrack`, `ip_tables`, `vxlan` all load; `net.ipv4.ip_forward=1`;
`bridge-nf-call-iptables=1`; ports 6443 / 10250 / 8472 / 51820 all free; NTP synchronised; ufw
**inactive**; Docker installed; **no k3s and no kubectl yet**. `wireguard-tools` is **not**
installed — that is the first apt step below.

**Networking reality.** Inter-node RTT is 0.44 ms (same datacentre) but there is **no private
interface**. Both hosts have only /32 public addresses on `ens3` and reach each other via the
public gateway `51.79.64.1`. Every packet between the nodes — cluster control plane, kubelet,
flannel VXLAN, Postgres, Redis, and every image byte read out of ceph — therefore rides
WireGuard. **No data service may ever bind a public address.**

**Security fact you must hold in your head the whole way through** (verified in
`backend/model/Media.py`): ceph buckets are created with `ACL='public-read'`, every upload sets
`public-read`, and there is a bucket policy with `Principal "*"`. The object store is
**anonymously readable by design** — the app serves direct media URLs out of it. That is safe
today only because it lives on a host-local Docker bridge. After the split it must be reachable
only through the cluster network. This is why `data/ceph.yaml` drops the `8080:8080` publish, why
the ceph Service is ClusterIP, and why `data/networkpolicy.yaml` exists.

**The cutover is not a DNS switch.** The k3s app tier runs on the *same software node* behind the
*same public IP* as the live compose stack. Compose nginx and a k3s ingress cannot both hold
`:80`/`:443`. So: build in parallel, validate on alternate ports, then swap ports on one host.
DNS changes only if the entry point moves to the data node, which this plan does not do.

---

## 1. Preflight — five things that are wrong or missing right now

Do these before you touch a server. Four of them are cheap; the first one will otherwise waste an
afternoon at exactly the wrong moment.

### 1.1 (!) The backend references five PVC names that no manifest creates

`k8s/app/10-maniwani.yaml` mounts the scraper volumes by claim name:

```
data-fourchan-aggregator-0   data-eightchan-aggregator-0   data-sevenchan-aggregator-0
data-reddit-aggregator-0     data-generic-aggregator-0
```

Its header explains that those are `volumeClaimTemplate` derived names. **The aggregator group
does not use volumeClaimTemplates.** `k8s/aggregators/1*.yaml` each declare a *standalone* PVC and
mount it by claim name:

```
aggregator-4chan   aggregator-8chan   aggregator-7chan   aggregator-reddit   aggregator-generic
```

Nothing in the cluster will ever be called `data-fourchan-aggregator-0`. The backend pod will sit
in `Pending` on five unbound claims, the site will be down, and the pod logs will say nothing
because the container never starts.

Verify, then fix in `k8s/app/10-maniwani.yaml` (the aggregator group is authoritative — it is the
manifest that actually creates the objects):

```bash
grep -n 'claimName: data-.*-aggregator-0' k8s/app/10-maniwani.yaml   # expect 5 hits
grep -rn '^  name: aggregator-' k8s/aggregators/                     # expect 5 PVCs
```

Five one-line edits, `data-fourchan-aggregator-0` → `aggregator-4chan`, and so on. After the
first apply, confirm with `kubectl -n maniwani get pvc` and `kubectl -n maniwani describe pod
maniwani-0 | tail -20`.

### 1.2 The shared log directory has two different paths

`k8s/app/*` and `k8s/aggregators/*` mount `hostPath: /var/log/maniwani`. `k8s/media/*` (rtmp,
seedbox, clamav, ergo) mount `hostPath: /var/lib/maniwani/logs`. Compose has exactly one
directory (`./maniwani_logs`). This is already flagged as a bug in
`aggregators/00-scraper-common-configmap.yaml`.

It is not a blocker — logging degrades to two trees, not to failure — so **do not fix it during
the migration**. Create both directories (§4.4) and open a ticket. Fixing it later is one path
string in four files; fixing it mid-cutover means re-rolling four StatefulSets.

### 1.3 Two manifests do not exist yet

* `k8s/app/40-nginx.yaml` — the edge. Referenced by `app/00-configmaps.yaml` (which carries the
  patched `nginx.conf`) and by `app/10-maniwani.yaml`. **§10 and §11 of this runbook assume it
  exists**, with container ports 80/443 and `hostPort` 8081/8443 pre-cutover, and
  `strategy: Recreate` (a RollingUpdate Deployment holding a hostPort deadlocks on itself — the
  new pod cannot bind a port the old pod still holds).
* A falco DaemonSet — `media/00-media-common.yaml` lists falco as a group member. See §13.3 for
  what to do with the compose falco in the meantime.

### 1.4 Host port 8080 on the software node is already taken

`docker-compose.yml` publishes ceph on `8080:8080` (`0.0.0.0`). So the "validate on 8080/8443"
plan collides with production until compose ceph is stopped. This runbook uses **8081/8443** for
validation to remove the ordering dependency. Check before you commit to a number:

```bash
sudo ss -lntp | grep -E ':(80|443|8080|8081|8443|1935|119|6443|10250)\b'
```

### 1.5 Drop the DNS TTL now, not later

`syndichan.org` and `node.syndichan.org` are both at ~300 s TTL at name.com. This plan does not
change DNS — but lower the TTL to 60 s a day beforehand anyway. It costs nothing and it converts
"we must roll back" from a 5-minute problem into a 1-minute one if you ever *do* need to move the
A record. `www.syndichan.org` has no A record; if you intend to serve it, that is a separate
change involving a new certificate SAN, and it is out of scope here.

---

## 2. WireGuard

### 2.1 Install (both nodes)

```bash
sudo apt-get update
sudo apt-get install -y wireguard-tools
```

The kernel module is already present (`CONFIG_WIREGUARD=m`, verified loading). Only the userspace
tools are missing. `wireguard-tools` pulls in `wg-quick` and the systemd unit template.

### 2.2 Why 10.99.0.0/24 and never 10.42.x or 10.43.x

k3s defaults to **cluster-cidr `10.42.0.0/16`** (pod addresses) and **service-cidr `10.43.0.0/16`**
(ClusterIPs). A WireGuard subnet inside either range creates a routing conflict that is
catastrophic and extremely hard to read: `wg-quick` installs a route for its `AllowedIPs`, that
route overlaps the CNI's, and pod-to-pod or pod-to-Service traffic starts silently vanishing into
the tunnel. `10.99.0.0/24` is outside both, outside the Docker bridge (`172.18.0.0/16`, pinned in
`docker-compose.yml`), and outside the default `172.17.0.0/16`.

This also settles a related question: **`AllowedIPs` must not list 10.42/10.43 either.** Pod
traffic does not ride the tunnel as bare pod IPs — flannel wraps it in VXLAN (UDP 8472) between
the two *WireGuard* addresses. The tunnel only ever carries `10.99.0.1 ↔ 10.99.0.2`, so `/32`
entries are correct and sufficient. Adding pod/service CIDRs to `AllowedIPs` would install routes
that fight the CNI.

### 2.3 Keys, without putting a private key in a config file or in your shell history

On **each** node:

```bash
sudo install -d -m 0700 /etc/wireguard
umask 077
wg genkey | sudo tee /etc/wireguard/privatekey >/dev/null
sudo chmod 0600 /etc/wireguard/privatekey
sudo cat /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
```

The last line prints the **public** key — that is the only value you exchange between the hosts,
and it is not a secret. The private key never leaves `/etc/wireguard/privatekey`, because the
configs below load it with `PostUp` instead of embedding it.

### 2.4 Config — software node `vps-8e766dc0`

`/etc/wireguard/wg0.conf`, mode `0600`:

```ini
[Interface]
Address    = 10.99.0.1/24
ListenPort = 51820
# MTU 1420 = 1500 (ens3) - 60 (WireGuard/IPv4/UDP overhead), with slack.
# Do NOT hand-tune this: flannel derives its own MTU as (wg0 MTU - 50) = 1370.
# Getting it wrong shows up as large S3 reads hanging while small ones work.
MTU        = 1420
# The private key is NOT stored in this file. wg-quick runs this after creating
# the interface, so the key stays in one 0600 file and never enters a config,
# a backup of this file, or your shell history.
PostUp     = wg set %i private-key /etc/wireguard/privatekey

[Peer]
# DATA node vps-56548ec0
PublicKey  = <PASTE_DATA_NODE_PUBLIC_KEY>
# Only the peer's tunnel address. Pod (10.42/16) and Service (10.43/16) traffic
# rides INSIDE flannel VXLAN between these two addresses and must not be listed.
AllowedIPs = 10.99.0.2/32
Endpoint   = 148.113.203.46:51820
```

### 2.5 Config — data node `vps-56548ec0`

`/etc/wireguard/wg0.conf`, mode `0600`:

```ini
[Interface]
Address    = 10.99.0.2/24
ListenPort = 51820
MTU        = 1420
PostUp     = wg set %i private-key /etc/wireguard/privatekey

[Peer]
# SOFTWARE node vps-8e766dc0
PublicKey  = <PASTE_SOFTWARE_NODE_PUBLIC_KEY>
AllowedIPs = 10.99.0.1/32
Endpoint   = 51.79.71.153:51820
# Only on this side: the data node is the one that benefits from holding the
# session open through any stateful middlebox. Harmless if it is unnecessary.
PersistentKeepalive = 25
```

### 2.6 Bring up and verify

```bash
sudo chmod 0600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
sudo systemctl status wg-quick@wg0 --no-pager
sudo wg show            # expect a recent handshake and non-zero transfer both ways
```

From the software node:

```bash
ping -c4 -W2 10.99.0.2
ip route get 10.99.0.2          # must say "dev wg0", NOT via 51.79.64.1
```

Measure the link now — §9.4's transfer estimate depends on it, and this is the only number in the
whole plan nobody has measured yet:

```bash
sudo apt-get install -y iperf3
# data node:      iperf3 -s -B 10.99.0.2
# software node:  iperf3 -c 10.99.0.2 -t 20
```

Record the result. WireGuard on 4 vCPU will typically saturate a 1 Gbit/s link; if you see much
less, the provider link is the limit, not the tunnel.

**Nothing on the live site has changed at this point.** WireGuard is an additional interface;
compose has not been touched.

---

## 3. k3s

### 3.1 Pick and record one version

```bash
# Ask for the current stable channel, then PIN it. Both nodes must match.
curl -sL https://update.k3s.io/v1-release/channels/stable
export K3S_VERSION=<the vX.Y.Z+k3s1 you just read>
```

Write that string down. An agent one minor behind its server is supported; two is not, and
"whatever `get.k3s.io` served that day" is not a version you can reproduce.

### 3.2 Server — software node

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" sh -s - server \
  --node-ip 10.99.0.1 \
  --advertise-address 10.99.0.1 \
  --flannel-iface wg0 \
  --node-label maniwani.io/role=software \
  --disable traefik \
  --disable servicelb \
  --secrets-encryption \
  --kubelet-arg='eviction-hard=memory.available<500Mi' \
  --kubelet-arg=container-log-max-size=10Mi \
  --kubelet-arg=container-log-max-files=3
```

Flag by flag, because each one is load-bearing:

* `--node-ip 10.99.0.1` / `--advertise-address 10.99.0.1` — the node registers its address, and
  the API server advertises itself, on the tunnel. Without these, kubelet registers the public
  /32 and every cross-node connection (apiserver→kubelet, kubelet→apiserver, Service traffic)
  routes over the public gateway in cleartext.
* `--flannel-iface wg0` — pins the VXLAN underlay to the tunnel. This is the flag that makes pod
  traffic private.
* `--disable traefik` — we run our own nginx edge. Traefik would also fight for :80/:443.
* `--disable servicelb` — `data/10-postgres.yaml` requires it explicitly: with klipper-lb
  present, a `type: LoadBalancer` Service created by mistake materialises a DaemonSet that binds
  `0.0.0.0` on the node, which for postgres/redis/ceph is a full compromise. Removing the
  mechanism is better than remembering not to use it.
* `--secrets-encryption` — k3s stores Secrets in its datastore in plaintext otherwise, and this
  namespace's Secrets include the site's Anubis signing key and every API credential. Must be set
  at install time; enabling it later needs a restart plus a re-encrypt pass.
* `--kubelet-arg='eviction-hard=...'` — **the quotes are mandatory.** Unquoted, the shell reads
  `<500Mi` as a redirect and silently truncates the flag. Required by
  `data/00-priorityclass.yaml`: on a no-swap node, eviction with headroom is the only thing
  between "the redis cache grew" and "the kernel OOM-killed the OSD holding every image on the
  site".
* `container-log-max-*` — required by `data/ceph.yaml` note 7. Compose capped ceph's json-file
  log at 10m × 3; in Kubernetes that is a node-level kubelet setting, and ceph's stderr will
  otherwise fill the same disk as its own data.

**Do NOT pass `--disable-network-policy`.** k3s ships kube-router as its policy controller and
enables it by default. Disabling it makes every NetworkPolicy in `data/` and `aggregators/`
silently inert while still appearing in `kubectl get netpol` — i.e. it *looks* like the data tier
is protected. Verify:

```bash
grep -c 'disable-network-policy' /etc/systemd/system/k3s.service   # expect 0
```

**Do not pass `--write-kubeconfig-mode 0644`** either, however many blog posts suggest it: that
makes cluster-admin credentials world-readable. Give the operator account its own copy instead:

```bash
install -d -m 0700 ~/.kube
sudo install -o "$USER" -g "$USER" -m 0600 /etc/rancher/k3s/k3s.yaml ~/.kube/config
kubectl get nodes -o wide     # expect vps-8e766dc0, INTERNAL-IP 10.99.0.1
```

### 3.3 Agent — data node

```bash
# Read the join token straight off the server into a variable. The VALUE is
# never printed and never appears in your history — only this command is.
K3S_TOKEN="$(ssh ubuntu@10.99.0.1 sudo cat /var/lib/rancher/k3s/server/node-token)"

curl -sfL https://get.k3s.io | \
  INSTALL_K3S_VERSION="$K3S_VERSION" \
  K3S_URL=https://10.99.0.1:6443 \
  K3S_TOKEN="$K3S_TOKEN" \
  sh -s - agent \
    --node-ip 10.99.0.2 \
    --flannel-iface wg0 \
    --node-label maniwani.io/role=data \
    --kubelet-arg='eviction-hard=memory.available<500Mi' \
    --kubelet-arg=container-log-max-size=10Mi \
    --kubelet-arg=container-log-max-files=3

unset K3S_TOKEN
```

The token ends up in `/etc/systemd/system/k3s-agent.service.env` (mode 0600). That is expected and
is where k3s wants it.

`K3S_URL=https://10.99.0.1:6443` is what forces the join over the tunnel. If you ever see the
public IP in `kubectl get nodes -o wide`, the cluster is talking to itself over the internet —
stop and fix it, do not "come back to it later".

### 3.4 Verify the cluster is actually private

```bash
kubectl get nodes -o wide
# NAME           STATUS   INTERNAL-IP   EXTERNAL-IP
# vps-8e766dc0   Ready    10.99.0.1     <none>
# vps-56548ec0   Ready    10.99.0.2     <none>

kubectl get node vps-56548ec0 -o jsonpath='{.status.addresses}{"\n"}'
sudo wg show wg0 transfer      # both counters climbing = cluster traffic is in the tunnel
```

### 3.5 Docker and k3s on the same host — what actually happens

Docker keeps running the live stack; k3s uses containerd and its own image store. They coexist,
but two interactions are worth knowing:

* Docker sets the iptables `FORWARD` policy to `DROP`. Flannel installs explicit `ACCEPT` rules
  for the pod CIDR, so pod networking is not broken by it. (This is the single most common
  "k3s on a Docker host doesn't work" report, and it does not apply here.)
* Both write iptables rules through the nft backend, alongside the 153 Docker-generated nftables
  rules already on the software node. Neither flushes the other's chains. Do not run
  `iptables -F` on this host, ever.

---

## 4. Node labels, namespace, storage classes, host directories

### 4.1 Labels

`--node-label` only applies at first registration. Verify — and if either is missing (a re-join, a
typo), set it by hand; it is idempotent:

```bash
kubectl get nodes -L maniwani.io/role
kubectl label node vps-8e766dc0 maniwani.io/role=software --overwrite
kubectl label node vps-56548ec0 maniwani.io/role=data     --overwrite
```

Every workload manifest in this repo selects on this label. Get it wrong and pods sit `Pending`
with `didn't match Pod's node affinity/selector` — loud, which is the design.

### 4.2 Namespace and storage classes

```bash
kubectl apply -k k8s/bootstrap/
kubectl get ns maniwani --show-labels
kubectl get storageclass
```

`kubectl get storageclass` will show three: `local-path` (k3s's own, marked default) plus
`maniwani-local` and `maniwani-data`. Read `storageclass.yaml`'s header for how the pinning
actually works and why `local-path` being default is a trap worth auditing for.

### 4.3 Optional: make the pin provisioner-enforced

Scheduling (WaitForFirstConsumer + the pods' `nodeSelector`) is what pins a volume to a node. If
you also want the *provisioner* to refuse to create a directory on the wrong node, and your
local-path-provisioner is v0.0.24+, give each class its own `nodePathMap` with exactly one node
and no default path:

```bash
kubectl -n kube-system get deploy local-path-provisioner \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

k3s re-applies its packaged copy of that manifest on every restart, so customise it by editing
`/var/lib/rancher/k3s/server/manifests/local-storage.yaml` **and** creating
`local-storage.yaml.skip` next to it — never with `kubectl edit`, which will be reverted.

This is hardening. Skip it on the first pass if you want fewer moving parts.

### 4.4 Host directories, on the software node

```bash
# Shared log trees. BOTH paths, because of the inconsistency in §1.2.
sudo mkdir -p /var/log/maniwani /var/lib/maniwani/logs
sudo chmod 0777 /var/log/maniwani /var/lib/maniwani/logs

# Static PV roots for the relink-in-place migration (§9.5).
sudo mkdir -p /var/lib/maniwani/pv
```

`hostPath: DirectoryOrCreate` would create these as `root:root 0755`; the per-pod initContainers
then widen them. Pre-creating them 0777 removes a first-boot ordering wobble. The tree genuinely
has to be world-writable: the backend image ends with `USER maniwani` and the aggregators run as
assorted uids.

**Check that the PV root and the Docker volume root are the same filesystem** — §9.5 depends on
`mv` being a rename rather than a copy:

```bash
stat -c '%d %n' /var/lib/docker/volumes /var/lib/maniwani/pv
```

Same device number → `mv` is instantaneous and needs no free space. Different → every "move"
below is a byte-for-byte local copy; still no network, but budget ~28 GB and real time.

---

## 5. Secrets

Source of truth: `/home/ubuntu/maniwani/.env` **on the software node** (126 keys, real
credentials). The copy in this git checkout is a different, smaller file and is **not** production
config. `k8s/bootstrap/secret.example.yaml` is the key inventory; read it alongside this section.

Turn off history for this shell first — belt and braces, since none of the commands below place a
value in argv anyway:

```bash
set +o history
```

### 5.1 `maniwani-dotenv` — the whole file

```bash
kubectl -n maniwani create secret generic maniwani-dotenv \
  --from-file=.env=/home/ubuntu/maniwani/.env
```

**Make the eight required `.env` edits first** — they are listed in
`secret.example.yaml` under the `maniwani-dotenv` document (`TRUSTED_PROXY_CIDRS`,
`RTMP_INGEST_URL`, `TORRENT_PUBLIC_HOST`, and the five/six aggregator + classifier URLs). All are
silent-failure class: the site comes up looking perfectly healthy and behaves subtly wrong.
`TRUSTED_PROXY_CIDRS` in particular decides whether every visitor IP on the site collapses into
the nginx pod's address.

If you re-edit `.env` later, replace the Secret and restart the backend:

```bash
kubectl -n maniwani create secret generic maniwani-dotenv \
  --from-file=.env=/home/ubuntu/maniwani/.env --dry-run=client -o yaml | kubectl apply -f -
kubectl -n maniwani rollout restart statefulset/maniwani
```

### 5.2 `maniwani-env` — the per-key subset, including the POSTGRES gap

Two groups of keys: those already in `.env` (copy them, never retype), and those that are **not**
in `.env` and must be added or the pods will not start.

**The gap.** `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB` are inline literals in
`docker-compose.yml` (`services.postgres.environment`) and do **not** exist in `.env`.
`data/10-postgres.yaml` consumes all three via `secretKeyRef` and deliberately does **not** mark
them optional, so a missing key leaves postgres in `CreateContainerConfigError` — i.e. no
database, no site. `S3_ACCESS_KEY` / `S3_SECRET_KEY` are likewise required by
`storage/10-syndichan-node.yaml`; they authenticate the primary storage-node S3
gateway and must be shared by the backend.

Read the values out of `docker-compose.yml` on the software node — do not type them from memory;
the postgres pair is also encoded in `deploy-configs/maniwani.cfg`'s `SQLALCHEMY_DATABASE_URI`,
and all three copies must agree.

```bash
umask 077
d="$(mktemp -d)"; cd "$d"

# (a) the keys that already exist in the live .env — copied, never displayed.
grep -E '^(ANUBIS_ED25519_PRIVATE_KEY_HEX|FALCO_INGEST_TOKEN|DOMAIN|TORRENT_PUBLIC_HOST|TORRENT_PUBLIC_SECURE|TORRENT_TURN_HOST|TORRENT_TURN_EXTERNAL_IP|TORRENT_TURN_PORT|TORRENT_TURNS_PORT|TORRENT_TURN_MIN_PORT|TORRENT_TURN_MAX_PORT|TORRENT_TURN_USERNAME|TORRENT_TURN_PASSWORD)=' \
  /home/ubuntu/maniwani/.env > subset.env

# Sanity: kubectl's --from-env-file parser does NOT strip quotes, so a quoted
# value would be imported WITH its quotes. Expect 0.
grep -c '="' subset.env

# (b) the keys that are missing. Typed, echo suppressed, never in argv or history.
for k in POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB \
         S3_ACCESS_KEY S3_SECRET_KEY DOMAIN_ALIASES; do
  printf '%s: ' "$k" >&2; IFS= read -rs v; printf '\n' >&2
  printf '%s=%s\n' "$k" "$v" >> subset.env
done
unset v

# (c) optional hardening keys for nntp-hub; skip to leave them unset.
#     NNTP_HUB_ALLOW  NNTP_HUB_ADMIN_TOKEN

kubectl -n maniwani create secret generic maniwani-env --from-env-file=subset.env

# Verify by KEY NAME only — this prints no values.
kubectl -n maniwani get secret maniwani-env -o jsonpath='{range .data}{""}{end}' >/dev/null
kubectl -n maniwani describe secret maniwani-env

shred -u subset.env; cd /; rmdir "$d"
```

**Cutover opportunity, deliberately noted here and nowhere else:** the k3s postgres is a brand-new
instance. This is the cheapest moment this project will ever have to stop using `dev/dev/dev`. If
you take it, change the Secret values, the `SQLALCHEMY_DATABASE_URI` in the `maniwani-cfg`
ConfigMap and the backend's `POSTGRES_*` in the **same** change — and do the dump/restore with the
new credentials. If you are not going to do all three, do none of them; a half-rotation is worse
than no rotation.

### 5.3 `ergo-ircd-config`

```bash
kubectl -n maniwani create secret generic ergo-ircd-config \
  --from-file=ircd.yaml=/home/ubuntu/maniwani/deploy-configs/ergo/ircd.yaml
```

From the **live** file. The `opers.sysop.password` bcrypt hash committed to this repo is a cost-04
placeholder, i.e. not the real credential.

### 5.4 `maniwani-tls` — and the honest story about certbot

The live certificate is Let's Encrypt, valid to **18 Oct 2026**, issued by certbot **on the
software node**, installed by `deploy-configs/certbot/renew-cert.sh` (systemd timer
`maniwani-cert-renew.timer`) into `/home/ubuntu/maniwani/deploy-configs/tls/{fullchain,privkey}.pem`.

```bash
kubectl -n maniwani create secret tls maniwani-tls \
  --cert=/home/ubuntu/maniwani/deploy-configs/tls/fullchain.pem \
  --key=/home/ubuntu/maniwani/deploy-configs/tls/privkey.pem
```

Three things you must understand about this Secret:

1. **It is a snapshot, not a link.** Certbot rewrites the pair on the host every ~60 days; this
   Secret does not follow. Re-import after every renewal:
   ```bash
   kubectl -n maniwani create secret tls maniwani-tls \
     --cert=/home/ubuntu/maniwani/deploy-configs/tls/fullchain.pem \
     --key=/home/ubuntu/maniwani/deploy-configs/tls/privkey.pem \
     --dry-run=client -o yaml | kubectl apply -f -
   ```
   This is the likeliest thing in the entire migration to break silently, months later, at 3am.
2. **coturn does not use it, and probably the edge nginx should not either.**
   `media/40-coturn.yaml` deliberately mounts the TLS *directory* as a hostPath, so the existing
   renewal loop keeps working unchanged, and its header is explicit that nginx and coturn must
   move together or not at all. Keep the pair on hostPath for both; `maniwani-tls` exists for
   anything that needs a real `kubernetes.io/tls` object (and as the migration path to
   cert-manager later, which is the right end state — one change, both consumers).
3. **HTTP-01 needs port 80 to keep working across the swap.** `renew-cert.sh` probes
   `http://127.0.0.1/.well-known/acme-challenge/` and serves the challenge from
   `deploy-configs/acme-webroot`, which compose nginx mounts read-only. Whatever holds :80 after
   cutover must serve that same webroot at that same path, or renewal fails over to
   `--standalone`, which cannot bind :80 while the k3s edge holds it, and the script exits 0
   ("keeping existing cert") — **failing quietly, by design, for 60 days**. The k3s edge manifest
   must mount `hostPath: /home/ubuntu/maniwani/deploy-configs/acme-webroot` at `/acme-webroot`.
   And see §13.3 item 1: the script's tail must stop calling `docker compose restart`.

Re-enable history when you are done with this section: `set -o history`.

---

## 6. ufw — read this in full before you type `ufw enable`

**ufw is INACTIVE on both nodes today.** Turning it on during a live migration is a real risk, and
half of what people expect it to do, it will not do. Both halves matter.

### 6.1 Allow SSH before enabling. Not after.

`ufw enable` applies `default deny incoming` **immediately**, to the session you are typing in.

```bash
sudo ufw allow OpenSSH          # or: sudo ufw allow 22/tcp
sudo ufw show added             # read it back BEFORE enabling
```

Keep a second SSH session open while you enable, and have the provider's console/KVM ready. If you
are locked out of the software node you are locked out of the live site.

### 6.2 Docker's DNAT rules bypass ufw. So will k3s's hostPorts.

This is the part that surprises people, and it means ufw will **not** close the ports the compose
stack publishes.

Traffic to a published container port is DNAT'd in `nat/PREROUTING` and then traverses the
**FORWARD** path to the container — it never reaches the `INPUT` chain where ufw's rules live.
Docker additionally inserts its own `DOCKER-USER`/`DOCKER` chains ahead of ufw's. Net effect on
the software node today: `ufw deny 8002` changes nothing at all; the scraper admin APIs on
8002–8006 (including `POST /reset`, which wipes a scraper's storage) stay reachable from the
internet exactly as before.

**k3s behaves the same way after cutover.** hostPorts are implemented by the CNI portmap plugin as
DNAT in `nat/PREROUTING`; NodePorts by kube-proxy in `KUBE-SERVICES`, also in `PREROUTING`. Both
bypass `INPUT`, therefore both bypass ufw's default-deny.

So be clear about what ufw is and is not buying you here:

* **It does protect host-level listeners**: sshd, and — importantly — the k3s API on `:6443` and
  kubelet on `:10250`, which default to binding `0.0.0.0` and would otherwise be exposed on the
  public /32 of both nodes.
* **It does not gate any containerised service**, under compose or under k3s.

If you want to actually close a published port, the tools are `ufw route` rules (which act on the
FORWARD path), an explicit `iptables -I DOCKER-USER ...` rule, binding the publish to a specific
address in compose, or the provider's edge firewall. The scraper ports 8002–8006 are the obvious
candidate; note that `k8s/aggregators/*` already drops those publishes entirely, so the k3s
migration fixes that exposure for free.

### 6.3 Rules

Software node:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 51820/udp comment 'wireguard'
sudo ufw allow in on wg0 comment 'cluster traffic: 6443, 10250, 8472/vxlan, pg, redis, rgw'
sudo ufw allow 80,443/tcp comment 'public web'
sudo ufw allow 1935/tcp   comment 'rtmp ingest'
sudo ufw allow 119/tcp    comment 'nntp hub (restrict to the peer if you can)'
sudo ufw allow 3478,5349/tcp comment 'turn'
sudo ufw allow 3478,5349/udp comment 'turn'
sudo ufw allow 49152:49351/udp comment 'turn relay range'
```

Data node — the tight one, and the whole point of the split:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 51820/udp comment 'wireguard'
sudo ufw allow in on wg0 comment 'cluster traffic only'
# NOTHING ELSE. No 6443, no 10250, no 8080. Postgres, redis and the anonymously
# readable object store live here and must be reachable only through the tunnel.
```

One more edit before enabling, on **both** nodes: ufw's default FORWARD policy is `DROP`, which
breaks CNI-forwarded traffic on some setups.

```bash
sudo sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
grep DEFAULT_FORWARD_POLICY /etc/default/ufw
```

Then:

```bash
sudo ufw enable
sudo ufw status verbose
# From the SECOND session: confirm SSH still works, then:
kubectl get nodes                      # cluster still healthy
sudo wg show wg0 latest-handshakes     # tunnel still up
sudo ss -lntp | grep -E ':(80|443)\b'   # MUST show 0.0.0.0/*, never 127.0.0.1
curl -sI https://syndichan.org/ | head -1   # live site still 200
```

If anything above fails: `sudo ufw disable` restores the status quo instantly. ufw is not required
for the migration — it is an improvement you are making *while* you are in here. Treat it as
optional and back it out at the first sign of trouble.

---

## 7. Images

k3s cannot build. Every repo-built image must be built and loaded into containerd before the
manifests can start. The manifests all use `registry.local/<name>:latest` with
`imagePullPolicy: IfNotPresent` — `registry.local` does not resolve anywhere, and that is
deliberate: `IfNotPresent` + a locally imported image means k3s never tries to reach a registry.

### 7.1 The eleven images, from twelve compose services

**The four chan aggregators share one build context**, via the `x-scraper-common` YAML anchor in
`docker-compose.yml` (`build.context: ./board_aggregators/fourchan_aggregator_plus`). One image,
four StatefulSets, differing only by their per-service ConfigMap. `reddit-aggregator` has its own
context and its own image.

| image | build context | consumed by |
|---|---|---|
| `registry.local/maniwani:latest` | `.` with `-f backend/Dockerfile` | `app/10-maniwani.yaml` |
| `registry.local/maniwani-frontend:latest` | `./frontend` | `app/20-maniwani-frontend.yaml` |
| `registry.local/fourchan-aggregator-plus:latest` | `./board_aggregators/fourchan_aggregator_plus` | 4chan **+** 8chan **+** 7chan **+** generic |
| `registry.local/reddit-aggregator:latest` | `./reddit-aggregator` | `aggregators/14-*` |
| `registry.local/nsfw-classifier:latest` | `./nsfw-classifier` | `aggregators/20-*` |
| `registry.local/tracker:latest` | `./tracker-server` | `media/30-tracker.yaml` |
| `registry.local/seedbox:latest` | `./seedbox` | `media/20-seedbox.yaml` |
| `registry.local/rtmp:latest` | `./rtmp` | `media/10-rtmp.yaml` |
| `registry.local/clamav:latest` | `./clamav` | `media/50-clamav.yaml` |
| `registry.local/glados-tts:latest` | `./glados-tts` | `media/70-glados-tts.yaml` |
| `registry.local/nntp-hub:latest` | `./nntp-hub` | `media/80-nntp-hub.yaml` |

A twelfth context, `./deploy-configs/nginx`, becomes `registry.local/nginx:latest` once
`app/40-nginx.yaml` exists (§1.3).

```bash
cd /home/ubuntu/maniwani
docker build -f backend/Dockerfile -t registry.local/maniwani:latest .
docker build -t registry.local/maniwani-frontend:latest      ./frontend
docker build -t registry.local/fourchan-aggregator-plus:latest ./board_aggregators/fourchan_aggregator_plus
docker build -t registry.local/reddit-aggregator:latest      ./reddit-aggregator
docker build -t registry.local/nsfw-classifier:latest        ./nsfw-classifier
docker build -t registry.local/tracker:latest                ./tracker-server
docker build -t registry.local/seedbox:latest                ./seedbox
docker build -t registry.local/rtmp:latest                   ./rtmp
docker build -t registry.local/clamav:latest                 ./clamav
docker build -t registry.local/glados-tts:latest             ./glados-tts
docker build -t registry.local/nntp-hub:latest               ./nntp-hub
```

Two build notes that are not optional:

* **maniwani**: the Dockerfile is multi-stage (`dev`, then `prod`) and compose sets no `target:`,
  so the final stage `prod` is what ships. Never pass `--target dev` — that stage keeps nodejs,
  runs as root, and points `MANIWANI_CFG` at `devmode.cfg` (sqlite + file storage).
* **glados-tts**: the Dockerfile `git clone --depth 1`s upstream at HEAD and curls two ONNX models
  from a GitHub release *at build time*. It is not reproducible and the image is multi-GB. Build
  it once, well before cutover. Pulling or rebuilding it on cutover day, on the node serving live
  traffic, is a self-inflicted outage.

### 7.2 Import into containerd

Everything above runs on the software node, which is where all eleven are needed:

```bash
for i in maniwani maniwani-frontend fourchan-aggregator-plus reddit-aggregator \
         nsfw-classifier tracker seedbox rtmp clamav glados-tts nntp-hub; do
  echo "== $i"
  docker save "registry.local/$i:latest" | sudo k3s ctr images import -
done
sudo k3s ctr images ls | grep registry.local | awk '{print $1}'
```

### 7.3 Third-party images — pin them by digest before they move under you

The data node needs `postgres:17`, `redis` (**unpinned in compose — `latest`, now Redis 8.x**) and
`ceph/daemon` (**also a bare tag**). Each manifest explains why a floating tag here is a
correctness problem, not a hygiene one: a `ceph/daemon:latest` that has moved to a newer major
**will not open the existing monmap/bluestore**, and that is unrecoverable without rebuilding from
the buckets.

Take the digests from what is actually running today and move those exact images across:

```bash
# software node — capture what production is really running
for i in postgres:17 redis ceph/daemon; do
  docker image inspect --format '{{index .RepoDigests 0}}' "$i"
done

# data node — pull by digest, retag, import
docker pull  postgres@sha256:<digest> && docker tag  postgres@sha256:<digest> postgres:17
docker pull  redis@sha256:<digest>    && docker tag  redis@sha256:<digest>    redis:latest
docker pull  ceph/daemon@sha256:<digest> && docker tag ceph/daemon@sha256:<digest> ceph/daemon:latest
for i in postgres:17 redis:latest ceph/daemon:latest; do
  docker save "$i" | sudo k3s ctr images import -
done
```

The remaining third-party images (`ghcr.io/techarohq/anubis:v1.25.0`,
`ghcr.io/ergochat/ergo:v2.18.0`, `coturn/coturn:4.7.0-r2`, `alpine:3.20`,
`quay.io/redlib/redlib:latest`) are already version-pinned in the manifests and will pull normally.
`redlib` ships `replicas: 0` and is not running today.

---

## 8. Apply order

The authoritative, annotated sequence lives in `bootstrap/kustomization.yaml`. Short form:

```bash
kubectl apply -k k8s/bootstrap/                    # namespace + storage classes
kubectl apply -f k8s/data/00-priorityclass.yaml    # cluster-scoped; pods are REJECTED without it
#   --- Secrets, §5 ---
kubectl apply -f k8s/app/00-configmaps.yaml        # log-init-script is a cross-group dependency
kubectl apply -f k8s/data/10-postgres.yaml
kubectl apply -f k8s/data/20-redis.yaml
kubectl apply -f k8s/storage/10-syndichan-node.yaml
kubectl apply -f k8s/aggregators/                  # see §8.3 BEFORE this one
kubectl apply -f k8s/app/10-maniwani.yaml
kubectl apply -f k8s/app/20-maniwani-frontend.yaml
kubectl apply -f k8s/app/30-anubis.yaml
kubectl apply -f k8s/media/
#   --- k8s/app/40-nginx.yaml when it exists (§1.3) ---
kubectl apply -f k8s/data/networkpolicy.yaml       # LAST, and only once the tiers are verified
kubectl apply -f k8s/aggregators/90-networkpolicy.yaml
```

### 8.1 What this does to the live site: nothing

Every k3s workload is either internal (ClusterIP) or ships `replicas: 0` for the three that want
host ports the compose stack holds (`rtmp` 1935, `coturn` 3478/5349/49152-49351, `nntp-hub` 119).
The two stacks coexist. Expect these one-time surprises:

* Five Pod Security Admission **warnings** on `kubectl apply -f k8s/media/` — see
  `namespace.yaml`. They are inventory, not errors.
* Ceph takes minutes to bootstrap a fresh demo cluster; the backend blocks up to 300 s waiting for
  it. A cold start of the whole namespace is ~10 minutes end to end.

### 8.2 Verify ceph before you put 21 GB into it

Two checks from `data/ceph.yaml`, both cheap, both cost a full re-sync if skipped:

```bash
kubectl -n maniwani exec ceph-0 -- ls /var/lib/ceph/mon     # must print exactly: ceph-ceph
kubectl -n maniwani delete pod ceph-0                        # then, after it reschedules:
kubectl -n maniwani exec ceph-0 -- ceph -s                   # expect HEALTH_OK on a NEW pod IP
```

The second is the acceptance test for the monmap-reconcile initContainer. Run it **before** the
bucket sync, not after.

### 8.3 (!) Do not let a scraper boot on an empty volume

`aggregators/00-scraper-common-configmap.yaml` is explicit: the monitored boards, retention
setting, thread-monitor worker limit, registered thread list and the persisted last-ATTEMPT
rotation clock all live in `runtime_settings` **inside** each `.db` file. An empty volume does not
"re-crawl from scratch" — it de-links every already-imported thread, because the backend keys
imported content to `(SITE_KEY, source ids)` in Postgres.

The same hazard, pointed the other way, is why the k3s **backend** must not run against a restored
production database with empty scraper volumes: its aggregator sync would see nothing on the
scraper side.

So either seed the volumes before the aggregators first start (§9.5), or apply
`k8s/aggregators/` with the StatefulSets scaled to 0 and scale them up afterwards:

```bash
kubectl -n maniwani scale statefulset \
  fourchan-aggregator eightchan-aggregator sevenchan-aggregator \
  generic-aggregator reddit-aggregator --replicas=0
```

---

## 9. Data migration

### 9.0 Order of operations — the trap is in the sequencing, not the commands

Three constraints interlock, and doing them in the wrong order is how you corrupt something:

* the k3s backend must boot **once against an empty database** so `S3Storage` creates the four
  ceph buckets with the anonymous-read policy the `/s3/` path depends on (§9.4);
* the k3s backend must **not** run against a *restored production* database while the scraper
  volumes are empty (§8.3);
* the live compose backend and the k3s backend must **not** write the same scraper SQLite files at
  the same time (§9.5).

The sequence that satisfies all three:

1. Apply everything (§8). Empty postgres, empty ceph, empty scraper volumes. The backend boots,
   runs its migrations against the empty DB and **creates the ceph buckets**. Aggregator
   StatefulSets stay at `replicas: 0`.
2. Run the ceph bucket sync (§9.4) — hours or days ahead, it is the long pole.
3. Scale the k3s backend to 0: `kubectl -n maniwani scale statefulset/maniwani --replicas=0`.
4. Restore postgres (§9.2). The backend stays at 0 — a backend running on production data with
   empty scraper volumes is the de-link hazard from §8.3.
5. Either seed the scraper volumes now by **copy** and bring the backend + aggregators up for a
   full-fidelity rehearsal (§9.5, second option), or leave everything at 0 and do the **move** in
   the cutover window (§9.5, default). Both are supported; pick one and write it down.
6. Cutover (§11) re-runs 2 and 4 as fast delta passes and does 5 if you chose the move.

### 9.1 Exactly three datasets cross the wire

| dataset | size | method | crosses WireGuard? |
|---|---|---|---|
| postgres | 349 M | logical dump + restore | yes, seconds |
| redis | — | **nothing to migrate** | no |
| ceph objects | 21 G | bucket-level sync (rclone) | yes, the only big transfer |

**Everything else — ~28 GB of scraper, rtmp, seedbox, clamav, ergo and nntp-hub volumes — stays on
the software node and is relinked in place (§9.5). It is never copied across the network, and if
`/var/lib/docker` and `/var/lib/maniwani` share a filesystem (§4.4) it is never copied at all.**

### 9.2 postgres — 349 M, logical, twice

Not a file copy: a hot `rsync` of a running data directory is not crash-consistent. And the dump
**must include the non-public `analytics` schema** — `pg_dump -n public` silently drops it, and
`backend/update.py::_detect_schema_revision` infers the Alembic revision from those tables, so a
partial restore makes the backend re-run the wrong migrations on first boot.

Dump (software node, compose still serving; no credential is ever typed — the commands read the
container's own environment):

```bash
umask 077; mkdir -p ~/migration && cd ~/migration
cd /home/ubuntu/maniwani

docker compose exec -T postgres sh -c 'pg_dumpall -U "$POSTGRES_USER" --globals-only' \
  > ~/migration/globals.sql
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > ~/migration/maniwani.dump

ls -lh ~/migration/                                    # expect ~349 M-ish, compressed

# MUST list BOTH public and analytics. Run through the container so the host
# does not need postgres client tools installed.
docker compose exec -T postgres pg_restore -l < ~/migration/maniwani.dump | grep 'SCHEMA - '
```

Restore into the k3s postgres (`kubectl exec` bypasses NetworkPolicy, so no label games needed):

```bash
kubectl -n maniwani exec -i postgres-0 -- sh -c 'psql -U "$POSTGRES_USER" -d postgres' \
  < ~/migration/globals.sql            # "role already exists" is expected and harmless

kubectl -n maniwani exec -i postgres-0 -- \
  sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
  < ~/migration/maniwani.dump
```

`--clean --if-exists` is what makes the second (delta) pass in §11 a re-run rather than a
drop-database dance. Do not add `-j`: parallel restore cannot read a custom archive from stdin.

Verify:

```bash
kubectl -n maniwani exec postgres-0 -- sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dn"'
# and compare a few counts against the live DB
for t in post thread board slip; do
  echo -n "$t live: "; docker compose -f /home/ubuntu/maniwani/docker-compose.yml exec -T postgres \
    sh -c "psql -tAqU \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -c 'select count(*) from $t'"
  echo -n "$t k3s : "; kubectl -n maniwani exec postgres-0 -- \
    sh -c "psql -tAqU \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -c 'select count(*) from $t'"
done
```

Any Job you write to do this instead of `kubectl exec` needs the pod label
`maniwani.io/postgres-client: "true"` or `data/networkpolicy.yaml` will correctly refuse it.

### 9.3 redis — nothing to migrate, and that is the correct answer

Redis has no volume in compose, its command deletes any RDB at boot and disables snapshotting
(`redis-server --save ''`), and there is no AOF. It is a cache plus a pub/sub bus; every restart is
a designed-for full state loss. The k3s redis starts empty. Blast radius, so nobody panics at
cutover: every Anubis proof-of-work challenge is invalidated (a wave of re-challenges at the
edge), cached pages and fragments are dropped (a CPU spike on the backend), the presence map
empties and live-typing indicators reset. The backend's pub/sub pump reconnects on its own. **Do
not create a PVC for redis** — the first thing the container does is delete the file you would be
persisting.

### 9.4 ceph — 21 GB, bucket sync, not a file copy

> **Superseded:** Kubernetes Ceph has been retired. Do not create a new Ceph
> StatefulSet from the historical procedure below. For an already-running
> Kubernetes Ceph deployment, use
> `k8s/storage/README.md` and the copy-and-verify Job under
> `k8s/storage/migration/`; it copies directly into `syndichan-node` and leaves
> the source untouched for rollback. The remainder of this subsection is kept
> only as historical context for the original Compose-to-Kubernetes migration.

**Do not rsync `/var/lib/ceph`.** Two independent reasons, both from `data/ceph.yaml`: a hot copy
of BlueStore/OSD state is not crash-consistent (you get a cluster that mounts and then loses
objects), and the compose cluster's identity is pinned to `172.18.0.100` in both the monmap and
the generated `ceph.conf` — an address that cannot exist in k3s. The migration strategy is a
**fresh cluster on empty PVCs plus an object-level sync**, which is also what lets both clusters
run at once.

**Sync into buckets the backend has already created.** Let the k3s backend come up once against
the new ceph first: `S3Storage` creates each bucket with `ACL=public-read` plus the anonymous
bucket policy, and the `/s3/` read path depends on that. If rclone creates a bucket instead, it
will not carry the policy and every image 403s. For the same reason the destination remote sets
`acl=public-read` on every object.

**Buckets:** `attachments` (the bulk), `thumbs`, `previews` (may not exist until a video is
uploaded). **Skip `static`** — `S3Storage.update()` re-uploads it from the container image on every
backend boot, so syncing it is wasted bandwidth that gets overwritten anyway.

Size the job first:

```bash
cd /home/ubuntu/maniwani
for b in attachments thumbs previews; do
  echo "== $b"
  docker compose exec -T ceph radosgw-admin bucket stats --bucket="$b" 2>/dev/null \
    | grep -E 'num_objects|size_actual'
done
```

Run the sync as a Job **on the data node**, so the 21 GB is written locally and only read across
the tunnel. The old RGW is reachable at `10.99.0.1:8080` because compose publishes it on
`0.0.0.0`. The pod label is the escape hatch declared in `data/networkpolicy.yaml`.

```bash
cat > /tmp/ceph-sync.yaml <<'YAML'
apiVersion: batch/v1
kind: Job
metadata:
  name: ceph-bucket-sync
  namespace: maniwani
spec:
  backoffLimit: 4
  template:
    metadata:
      labels:
        app: ceph-bucket-sync
        app.kubernetes.io/name: ceph-bucket-sync
        app.kubernetes.io/part-of: maniwani
        maniwani.io/group: data
        maniwani.io/ceph-client: "true"   # required by data/networkpolicy.yaml
    spec:
      restartPolicy: OnFailure
      nodeSelector:
        maniwani.io/role: data
      automountServiceAccountToken: false
      containers:
        - name: rclone
          image: rclone/rclone:latest
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -eu
              for b in attachments thumbs; do
                echo "=== $b"
                rclone sync --size-only --transfers 8 --checkers 16 --retries 5 \
                  --stats 30s --stats-one-line "old:$b" "new:$b"
              done
              echo "=== previews (optional)"
              rclone sync --size-only --transfers 8 --checkers 16 --retries 5 \
                --stats 30s --stats-one-line "old:previews" "new:previews" \
                || echo "previews absent upstream - expected if no video was ever uploaded"
              echo "=== sizes"
              for b in attachments thumbs; do
                echo -n "old $b: "; rclone size "old:$b"
                echo -n "new $b: "; rclone size "new:$b"
              done
          env:
            - {name: RCLONE_CONFIG_OLD_TYPE,     value: s3}
            - {name: RCLONE_CONFIG_OLD_PROVIDER, value: Ceph}
            - {name: RCLONE_CONFIG_OLD_ENDPOINT, value: "http://10.99.0.1:8080"}
            - {name: RCLONE_CONFIG_NEW_TYPE,     value: s3}
            - {name: RCLONE_CONFIG_NEW_PROVIDER, value: Ceph}
            - {name: RCLONE_CONFIG_NEW_ENDPOINT, value: "http://ceph:8080"}
            # Anonymous public-read is how the app serves media; preserve it.
            - {name: RCLONE_CONFIG_NEW_ACL,      value: public-read}
            - name: RCLONE_CONFIG_OLD_ACCESS_KEY_ID
              valueFrom: {secretKeyRef: {name: maniwani-env, key: CEPH_DEMO_ACCESS_KEY}}
            - name: RCLONE_CONFIG_OLD_SECRET_ACCESS_KEY
              valueFrom: {secretKeyRef: {name: maniwani-env, key: CEPH_DEMO_SECRET_KEY}}
            - name: RCLONE_CONFIG_NEW_ACCESS_KEY_ID
              valueFrom: {secretKeyRef: {name: maniwani-env, key: CEPH_DEMO_ACCESS_KEY}}
            - name: RCLONE_CONFIG_NEW_SECRET_ACCESS_KEY
              valueFrom: {secretKeyRef: {name: maniwani-env, key: CEPH_DEMO_SECRET_KEY}}
          resources:
            requests: {cpu: 200m, memory: 256Mi}
            limits:   {memory: 1Gi}
YAML

kubectl apply -f /tmp/ceph-sync.yaml
kubectl -n maniwani logs -f job/ceph-bucket-sync
```

**`--size-only` is deliberate.** Media objects are written once and never rewritten in place, so
size is a sufficient comparison — and it makes the delta pass at cutover cost one LIST per bucket
instead of 21 GB of checksums. **Re-running the Job is the resume mechanism**: `rclone sync` skips
what already matches, which is the object-store equivalent of `rsync --partial`. Delete and
re-apply after any interruption; it is idempotent and safe.

**How long the 21 GB takes.** Nobody has measured this link yet — that is what §2.6's `iperf3`
run is for. The arithmetic, so you can plan from your own number:

| measured throughput | 21 GB takes |
|---|---|
| 100 Mbit/s (12.5 MB/s) | ~28 min |
| 250 Mbit/s (31 MB/s) | ~11 min |
| 1 Gbit/s (125 MB/s) | ~3 min |

Then adjust upward, because **this payload is object-count-bound, not byte-bound**: it is mostly
images and thumbnails, and each one costs a round trip plus an RGW write on a 4 vCPU node. With
`--transfers 8` on a directory-backed single-OSD demo cluster, expect the RGW, not the wire, to be
the limit. **Budget 45–90 minutes for the first full pass and plan to run it a day or more before
cutover.** The delta pass at cutover is minutes.

Verify with the sizes the Job prints, and then end-to-end from inside the cluster:

```bash
kubectl -n maniwani exec deploy/maniwani-frontend -- \
  wget -S -O /dev/null http://ceph:8080/thumbs/<a-known-thumb-key> 2>&1 | head -3
```

**Security follow-up, and schedule it:** while the compose ceph is running, port 8080 on
`51.79.71.153` serves every attachment on the site anonymously, with no Anubis challenge and no
rate limit. That is pre-existing, not something this migration introduces — but `docker compose
stop ceph` after the sync closes it, and the k3s replacement has no host publish at all. This is
the single largest exposure reduction in the whole project.

### 9.5 Everything else — relinked in place on the software node

Twelve volumes, ~28 GB, none of which touches the network. The mapping — verify the right-hand
column against `kubectl -n maniwani get pvc` before you move anything:

| docker volume | measured | k8s PVC | shape | writer |
|---|---|---|---|---|
| `maniwani_aggregator-4chan` | 4.3 G | `aggregator-4chan` | standalone PVC | fourchan-aggregator (+ backend) |
| `maniwani_aggregator-8chan` | 560 M | `aggregator-8chan` | standalone PVC | eightchan-aggregator (+ backend) |
| `maniwani_aggregator-7chan` | 666 M | `aggregator-7chan` | standalone PVC | sevenchan-aggregator (+ backend) |
| `maniwani_aggregator-generic` | 8.5 G | `aggregator-generic` | standalone PVC | generic-aggregator (+ backend) |
| `maniwani_aggregator-reddit` | 7 M | `aggregator-reddit` | standalone PVC | reddit-aggregator (+ backend) |
| `maniwani_rtmp-storage` | 8.2 G | `rtmp-storage` | standalone PVC | rtmp (read by backend + nginx) |
| `maniwani_maniwani-uploads` | tiny | `maniwani-uploads-maniwani-0` | vct on `maniwani` | backend |
| `maniwani_seedbox-data` | 5.6 G | `data-seedbox-0` | vct on `seedbox` | seedbox |
| `maniwani_clamav-data` | 168 M | `db-clamav-0` | vct on `clamav` | clamav |
| `maniwani_ergo-data` | tiny | `ircd-ergo-0` | vct on `ergo` | ergo |
| `maniwani_nntp-hub-data` | 48 M | `data-nntp-hub-0` | vct on `nntp-hub` | nntp-hub |
| `maniwani_compose-postgres` | 349 M | `data-postgres-0` | **§9.2, not moved** | — |
| `maniwani_compose-ceph`(+`-etc`) | 21 G | `data-ceph-0`, `etc-ceph-0` | **§9.4, not moved** | — |

**Method: a static `local` PersistentVolume per directory, not dynamic provisioning.** Dynamic
provisioning under `WaitForFirstConsumer` only creates the directory when a consuming pod is
scheduled — which for the scrapers means booting them against an empty volume first, exactly the
thing §8.3 forbids. A pre-created PV with a `claimRef` sidesteps it: the scheduler binds the
existing PV instead of provisioning, and the pod's first sight of the volume is the real data.

Per volume — worked example, `aggregator-4chan`:

```bash
VOL=maniwani_aggregator-4chan
PVC=aggregator-4chan
DST=/var/lib/maniwani/pv/$PVC
SRC=/var/lib/docker/volumes/$VOL/_data

# 1. STOP the writer. (Only this scraper. The site keeps serving.)
cd /home/ubuntu/maniwani && docker compose stop fourchan-aggregator

# 2. Record the truth BEFORE.
sudo find "$SRC" | wc -l ; sudo du -sb "$SRC"

# 3. MOVE. A rename on the same filesystem: instant, no free space needed.
sudo mkdir -p /var/lib/maniwani/pv
sudo mv "$SRC" "$DST"

# 4. Record the truth AFTER. Both numbers must match step 2 exactly.
sudo find "$DST" | wc -l ; sudo du -sb "$DST"

# 5. Publish it as a PV bound to the claim the manifest declares.
cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-$PVC
  labels: {app.kubernetes.io/part-of: maniwani, maniwani.io/relinked: "true"}
spec:
  capacity: {storage: 15Gi}          # documentation only; local-path enforces nothing
  accessModes: ["ReadWriteOnce"]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: maniwani-local
  local: {path: $DST}
  claimRef: {namespace: maniwani, name: $PVC}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - {key: kubernetes.io/hostname, operator: In, values: [vps-8e766dc0]}
YAML
```

Then apply the group and confirm the claim bound to *your* PV, not a fresh empty one:

```bash
kubectl -n maniwani get pvc aggregator-4chan -o wide     # VOLUME must read pv-aggregator-4chan
```

Notes that matter:

* A `mv` does **not** break a running container's mount. Mounts follow the inode, so a compose
  container that already has the directory mounted keeps working after the rename. Convenient, but
  do not rely on it as a plan — see the hazard below.
* For `volumeClaimTemplate`-backed claims (`data-seedbox-0`, `db-clamav-0`, `ircd-ergo-0`,
  `data-nntp-hub-0`, `maniwani-uploads-maniwani-0`) the StatefulSet creates the PVC only if it is
  missing, and a pre-bound PVC of the right name is adopted. Create the PVC yourself with the same
  `accessModes`/`storageClassName` as the template, or scale the StatefulSet to 1 just long enough
  for it to create the PVC and then scale back to 0 before moving data in.
* `clamav-data` is a virus signature database. If moving it is awkward, don't — `freshclam`
  rebuilds it. It is the one volume in this table that is genuinely disposable.

**(!) THE HAZARD THAT DECIDES YOUR SCHEDULE: the scraper SQLite files have two would-be writers.**
The backend does not only read them — it writes import state into them. If the live compose
backend and the parallel k3s backend both run against the *same* aggregator directories, they
fight over that state: one marks a thread imported, the other skips it, and content silently goes
missing from one of the two databases. **The live site is the one that loses.** Two safe options:

* **Move at cutover (default).** Leave the aggregator volumes alone until the `[WINDOW]`, then stop
  the compose aggregators *and* the compose backend and do the moves. They are renames — the whole
  table takes seconds. Cost: you validate the parallel stack with empty scraper volumes, so keep
  the k3s aggregators **and** the k3s backend's aggregator sync out of the picture until then.
* **Pre-copy for a fuller rehearsal.** `sudo cp -a "$SRC/." "$DST/"` into the PV directories now
  (≈28 GB against 97 GB free — it fits), validate the parallel stack against real data, then in the
  window run `sudo rsync -aHAX --numeric-ids --delete --partial --info=progress2 "$SRC/" "$DST/"`
  to pick up the delta. Costs disk and a second pass; buys a much better rehearsal. If you take
  this path, the copies are *copies* — the live stack is untouched and cannot be hurt by the k3s
  stack.

Use `rsync -aHAX --numeric-ids --partial` for every file-tree copy in this section. `--partial`
keeps a half-transferred file so an interrupted run resumes instead of restarting; `-H` preserves
hard links; `--numeric-ids` stops uid/gid remapping from silently changing ownership on data whose
uids come from container images.

---

## 10. Validate in parallel, on alternate ports

The k3s edge (`app/40-nginx.yaml`, §1.3) runs with `hostPort` **8081** and **8443** while compose
holds 80/443. 8081 rather than 8080 because compose publishes ceph on 8080 (§1.4).

```bash
kubectl -n maniwani get pods -o wide            # everything Running/Ready on the expected node
kubectl -n maniwani get pvc                     # every claim Bound, every class maniwani-*
kubectl get pv -o custom-columns=NAME:.metadata.name,CLAIM:.spec.claimRef.name,NODE:'.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0]',PATH:.spec.local.path

# The site, through the k3s edge, without touching production:
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: syndichan.org' http://127.0.0.1:8081/health
curl -skS -o /dev/null -w '%{http_code}\n' -H 'Host: syndichan.org' https://127.0.0.1:8443/
curl -skS -H 'Host: syndichan.org' https://127.0.0.1:8443/ | head -40

# The live site is still the live site:
curl -sI https://syndichan.org/ | head -1
```

Work down this list; each item is a thing that has actually broken in a migration like this one:

1. **CoreDNS resolver.** `app/00-configmaps.yaml` rewrites `resolver 127.0.0.11` (Docker's
   embedded DNS, nonexistent in k3s) to `10.43.0.10`. Confirm that is really CoreDNS's address:
   `kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}'`. Wrong value = every
   proxied location 502s while nginx itself looks perfectly healthy. This is the #1 landmine.
2. **A media read**, end to end: `/s3/thumbs/<id>.jpg` through the k3s edge, i.e. software node →
   WireGuard → data node RGW → back.
3. **An upload**, end to end: clamav scan → nsfw classifier → ceph write → thumbnail.
4. **X-Forwarded-For.** Post something and confirm the recorded IP is yours, not the nginx pod's.
   If every visitor shows the same address, `TRUSTED_PROXY_CIDRS` is wrong (§5.1).
5. **Anubis**, on a fresh browser profile: you should get the proof-of-work challenge, then the
   site.
6. **SSE/live updates** on a thread (`/api/v1/live`) — this exercises redis pub/sub across the
   tunnel.
7. **A scraper control call** from Admin → Scrapers (monitored boards, retention). This is what
   catches the `localhost:800X` aggregator-URL trap from §5.1.
8. **Restart resilience**: `kubectl -n maniwani delete pod ceph-0` and confirm HEALTH_OK on the new
   pod IP (§8.2). Do this before, not after, you depend on it.

Only after all eight, apply the NetworkPolicies (§8, step 10) and re-run 2, 3, 5 and 6. A
fail-closed policy with a label typo presents as "DNS resolves, Service exists, connection hangs".

---

## 11. `[WINDOW]` Cutover — a port swap, not a DNS change

**Expected downtime: 5–15 minutes**, dominated by the final postgres restore and the backend's
restart. The port swap itself is seconds. Everything expensive — images, ceph's 21 GB, the k3s
stack itself — is already warm.

Announce it, then:

```bash
#!/usr/bin/env bash
# k8s/bootstrap/cutover.sh  — run on the SOFTWARE node
set -euo pipefail
NS=maniwani
CD=/home/ubuntu/maniwani
cd "$CD"

echo "== 0. sanity: the k3s edge is on 8081/8443 and healthy"
kubectl -n "$NS" get deploy nginx \
  -o jsonpath='{.spec.template.spec.containers[0].ports[*].hostPort}{"\n"}'   # expect: 8081 8443

echo "== 1. stop the live edge. THE SITE IS DOWN FROM HERE."
docker compose stop nginx

echo "== 2. quiesce the live writers and free the remaining host ports"
docker compose stop maniwani rtmp coturn nntp-hub \
                    fourchan-aggregator eightchan-aggregator sevenchan-aggregator \
                    generic-aggregator reddit-aggregator seedbox

echo "== 3. final postgres delta (349 M; --clean --if-exists makes this a re-run)"
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > /tmp/final.dump
kubectl -n "$NS" scale statefulset/maniwani --replicas=0
kubectl -n "$NS" wait --for=delete pod/maniwani-0 --timeout=180s || true
kubectl -n "$NS" exec -i postgres-0 -- \
  sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' < /tmp/final.dump

echo "== 4. final ceph delta (re-running the Job is the resume mechanism)"
kubectl -n "$NS" delete job ceph-bucket-sync --ignore-not-found
kubectl -n "$NS" apply -f /tmp/ceph-sync.yaml
kubectl -n "$NS" wait --for=condition=complete job/ceph-bucket-sync --timeout=1800s

echo "== 5. relink the software-node volumes (renames; see §9.5 for the per-volume loop)"
#   ... run the §9.5 move (or the final rsync delta) for each row of the table ...

echo "== 6. move the k3s edge onto :80/:443"
# Scale to 0 first: a Deployment holding a hostPort cannot roll (the new pod
# would have to bind a port the old pod still holds).
kubectl -n "$NS" scale deploy/nginx --replicas=0
kubectl -n "$NS" wait --for=delete pod -l app=nginx --timeout=120s || true
# JSON-patch REPLACE on the whole ports array, not a strategic merge. The ports
# list merges by containerPort, so a merge patch would keep `hostIP: 127.0.0.1`
# and the edge would come back bound to loopback -- :443 answers locally while
# the public site stays dark.
kubectl -n "$NS" patch deploy/nginx --type=json -p '[
  {"op":"replace","path":"/spec/template/spec/containers/0/ports","value":[
    {"name":"http","containerPort":80,"protocol":"TCP","hostPort":80},
    {"name":"https","containerPort":443,"protocol":"TCP","hostPort":443}
  ]}
]'
kubectl -n "$NS" scale deploy/nginx --replicas=1

echo "== 7. bring up everything that was waiting on a host port"
kubectl -n "$NS" scale statefulset/rtmp     --replicas=1
kubectl -n "$NS" scale statefulset/nntp-hub --replicas=1
kubectl -n "$NS" scale deploy/coturn        --replicas=1
kubectl -n "$NS" scale statefulset/maniwani --replicas=1
kubectl -n "$NS" scale statefulset fourchan-aggregator eightchan-aggregator \
                 sevenchan-aggregator generic-aggregator reddit-aggregator --replicas=1

echo "== 8. wait, then smoke"
kubectl -n "$NS" rollout status deploy/nginx --timeout=180s
kubectl -n "$NS" rollout status statefulset/maniwani --timeout=600s
curl -sS  -o /dev/null -w 'http  %{http_code}\n' http://127.0.0.1/health
curl -skS -o /dev/null -w 'https %{http_code}\n' -H 'Host: syndichan.org' https://127.0.0.1/
curl -sI https://syndichan.org/ | head -1
echo "== done"
```

Then, without rushing: re-run the §10 checklist items 2–7 against the real ports, watch
`kubectl -n maniwani get pods -w` for a few minutes, and tail
`kubectl -n maniwani logs -f statefulset/maniwani`.

Leave the compose stack **stopped, not deleted**, for at least a week. `docker compose down -v`
would delete the named volumes, which are still the only copy of anything you did not migrate.

---

## 12. Rollback — one command back to compose

Valid for as long as you are willing to discard what happened on the k3s side. **Within the first
minutes it is lossless. It is not lossless later**: posts, uploads and stream recordings created
after the swap exist only in the k3s postgres and the k3s ceph. Rolling back after hours means
dumping the k3s database back into compose first (§9.2 in reverse) and re-syncing the buckets the
other way. Decide fast.

```bash
#!/usr/bin/env bash
# k8s/bootstrap/rollback.sh  — run on the SOFTWARE node
set -euo pipefail
NS=maniwani
cd /home/ubuntu/maniwani

# 1. release the host ports
kubectl -n "$NS" scale deploy/nginx --replicas=0
kubectl -n "$NS" wait --for=delete pod -l app=nginx --timeout=120s || true
kubectl -n "$NS" scale statefulset/rtmp --replicas=0
kubectl -n "$NS" scale statefulset/nntp-hub --replicas=0
kubectl -n "$NS" scale deploy/coturn --replicas=0

# 2. give the compose stack its ports back
docker compose start nginx maniwani rtmp coturn nntp-hub seedbox \
                     fourchan-aggregator eightchan-aggregator sevenchan-aggregator \
                     generic-aggregator reddit-aggregator

# 3. put the k3s edge back on the validation ports so it can keep running harmlessly
kubectl -n "$NS" patch deploy/nginx --type=json -p '[
  {"op":"replace","path":"/spec/template/spec/containers/0/ports","value":[
    {"name":"http","containerPort":80,"protocol":"TCP","hostPort":8081,"hostIP":"127.0.0.1"},
    {"name":"https","containerPort":443,"protocol":"TCP","hostPort":8443,"hostIP":"127.0.0.1"}
  ]}
]'
kubectl -n "$NS" scale deploy/nginx --replicas=1

curl -sI https://syndichan.org/ | head -1
```

**If you moved (rather than copied) the software-node volumes in step 5 of the cutover, reverse
those renames too** — compose will otherwise start those services on empty directories. That is
the strongest argument for the pre-copy variant in §9.5.

---

## 13. Deliberately not migrated, and post-cutover follow-ups

### 13.1 Not migrated: `autoheal`

`willfarrell/autoheal` existed only because Docker's restart policy fires on process **exit**, and
a wedged ceph OSD keeps running while failing its healthcheck (the documented symptom: every
`/upload/thumb` returning 500). Kubernetes restarts a container on `livenessProbe` failure
natively, so the whole workaround disappears. Verified: `autoheal=true` appears on exactly one
compose service (ceph), so nothing else loses cover. `data/ceph.yaml` reproduces the compose
healthcheck script verbatim as its livenessProbe.

Note the deliberate asymmetry: ceph **has** a liveness probe because "wedged but running" is its
real failure mode; postgres deliberately **does not**, because a long checkpoint or crash recovery
would trip it and the restart would kill the recovery it was supposed to fix.

### 13.2 Not migrated: `log-init`

The compose one-shot used `depends_on: condition: service_completed_successfully`. Kubernetes has
no equivalent for Deployments/StatefulSets, and a Job runs exactly once — it would not re-run
after a node reboot, a fresh volume or a cluster rebuild, leaving nginx unable to open its
error_log and dying at startup. So the script became an **idempotent initContainer**, run by every
pod that mounts the shared log tree, sourced from the `log-init-script` ConfigMap in
`app/00-configmaps.yaml`. `chmod -R 0777` is preserved verbatim: the backend runs as non-root, the
aggregators run as assorted uids, and `fsGroup` does not apply to hostPath volumes.

The end state is stdout-only logging plus the node's container log rotation, at which point the
hostPath, the initContainer and the §1.2 path inconsistency all disappear together. That is an
application change (rtmp's supervisord, clamav's tee-to-FIFO entrypoint and the Node logger all
write files by design) and is explicitly out of scope for the migration.

### 13.3 Follow-ups, in priority order

1. **`renew-cert.sh` still calls `docker compose restart nginx coturn`.** After cutover that
   restarts two stopped containers and the *running* pods never see the new certificate — which
   surfaces ~60 days later as an expired cert on a site that looks fine. Change the tail to
   `kubectl -n maniwani rollout restart deploy/nginx deploy/coturn`, and make sure whatever holds
   :80 serves `deploy-configs/acme-webroot` (§5.4). **Do this in the same week as the cutover.**
2. **Re-import `maniwani-tls` after every renewal**, or move both nginx and coturn to cert-manager
   in one change (§5.4).
3. **Falco.** There is no DaemonSet yet. The compose falco keeps working as a host IDS after
   cutover — modern-eBPF taps the kernel and sees containerd's containers too — but it loses
   container-name enrichment for k3s pods, and its `http_output.url` points at
   `http://maniwani:3032/...` on the Docker network, which stops existing when the compose backend
   stops. Either write the DaemonSet, or point the compose falco at the `maniwani` Service
   ClusterIP with host networking. Non-blocking: alerts stop reaching Admin → Falco; the site is
   unaffected.
4. **Stop `docker compose ceph`** once the buckets are verified — it closes the anonymous
   `51.79.71.153:8080` media read path (§9.4).
5. **Rotate `dev/dev/dev`** if you did not take the opportunity in §5.2.
6. **Add `requirepass` to redis.** It has no auth, no ACL and no TLS, and it now crosses a wire.
   Coordinated change across `.env`, `deploy-configs/maniwani.cfg` **and**
   `deploy-configs/anubis-policy.yaml` — after cutover, never during.
7. **Fix the log path split** (§1.2) and the PVC naming (§1.1, if you patched it locally rather
   than in git).
8. **Alerting on `kube_pod_container_status_restarts_total`** for this namespace. The four chan
   aggregators have *no* restart policy under compose — a crash leaves them down until someone
   notices. Under k8s they restart forever, which is what you want, but it means a crash-looping
   scraper is now invisible.
9. **Backups.** `storageclass.yaml` says it plainly: a PVC is a directory on one node's disk. The
   software node's 28 GB of scraper/rtmp/seedbox volumes have no backup today, under compose or
   under k3s. The migration does not change that, and it does not excuse it.
