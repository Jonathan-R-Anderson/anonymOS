# maniwani k3s updater — operator guide

**What it is:** an in-cluster CronJob pinned to the software node that polls
`git@github.com:Jonathan-R-Anderson/maniwani.git` `main` every 5 minutes. On a new commit it
builds only the images whose build context changed, imports them into containerd under an
**immutable `:g<short-sha>` tag**, runs migrations as a discrete Job, rolls the changed workloads
in tier order, verifies, and **on any failure re-applies the previous release and stops**.

**Your day-to-day is `git push`. Nothing else. You read failures in a browser.**

Every run writes a log and a status JSON to `/var/lib/maniwani/deploy/` on the software node,
which the existing nginx edge serves at **`https://syndichan.org/_deploy/`** behind HTTP Basic.
No SSH in the happy path, and no SSH needed to read the failure.

> **Read §8 before you trust this thing with a schema change.** A forward Alembic migration that
> has already committed is **not** undone by rolling the image back, and reverting the backend
> image alone after a migration does not "risk incompatibility" — in this codebase it
> *deterministically crashes at boot*. §8 says exactly what is and is not recoverable.

---

## Contents

| § | |
|---|---|
| [1](#1-architecture-at-a-glance) | Architecture at a glance |
| [2](#2-one-time-setup) | One-time setup — exact commands |
| [3](#3-triggering-an-update-without-ssh) | Triggering an update **without SSH** |
| [4](#4-reading-the-error-log-without-ssh) | Reading the error log **without SSH** |
| [5](#5-what-a-run-actually-does) | What a run actually does (gates, change map, order, timeouts) |
| [6](#6-automatic-rollback) | Automatic rollback — what it covers |
| [7](#7-manual-rollback-when-the-automatic-one-fails) | **Manual rollback** when the automatic one fails |
| [8](#8-what-is-not-covered-database-migrations) | **What is NOT covered: database migrations** |
| [9](#9-retention) | Retention — image tags and log rotation |
| [10](#10-troubleshooting) | **Troubleshooting table** — symptom → cause → command |
| [11](#11-configuration-reference) | Configuration reference |
| [12](#12-known-limitations) | Known limitations, stated plainly |
| [A](#appendix-a-files-in-this-directory) | Appendix A: files in this directory |

---

## 1. Architecture at a glance

```
  you ──git push──► github.com/Jonathan-R-Anderson/maniwani  main
                              │
                              │  (poll, every 5 min, read-only deploy key)
                              ▼
  software node vps-8e766dc0 ── CronJob: maniwani-updater
                              │
                              ├─ 1. fetch, gate, render manifests with :g<sha>
                              ├─ 2. docker build   (only changed contexts)
                              ├─ 3. k3s ctr images import
                              ├─ 4. pg_dump  +  Job/maniwani-migrate-<sha>
                              ├─ 5. kubectl apply, tier A→B→C→D
                              ├─ 6. smoke test
                              └─ on ANY failure: re-apply render/<prev-sha>/, stop
                              │
                              ▼
  /var/lib/maniwani/deploy/  ──mounted read-only──►  nginx edge
                                                      │
  you ◄────── https://syndichan.org/_deploy/ ─────────┘   (HTTP Basic, no Anubis)
```

**Why systemd on the host and not a CronJob in the cluster.** The build needs `docker` and the
import needs `k3s ctr`; both are host tools. The in-cluster alternative means mounting
`/var/run/docker.sock` into namespace `maniwani` — **that is root on the software node, granted to
the namespace that also runs the public edge, a Flask app with an upload/image-proxy/scraper
attack surface, and seven scrapers that parse hostile HTML.** Anyone who gets `create pods` in that
namespace then gets `docker run -v /:/host --privileged` and owns the node, including the
WireGuard key that reaches the data node. Today that path does not exist; adding it for a
convenience feature would be the single largest blast-radius change available in this stack, and
it buys nothing. Falco is running as a DaemonSet here and a pod mounting docker.sock is exactly
what its rules should be screaming about.

**What that does not avoid, and I will not pretend it does:** the updater is by construction a
remote-code-execution channel from GitHub `main` to root on the software node. `docker build`
executes `RUN` lines as root. There is no sandbox that changes this while letting the repo define
its own Dockerfiles. The mitigation is *upstream* — branch protection, required review,
`REQUIRE_SIGNED=1` (§11) — not container isolation. See §12.

**The updater's cluster identity is deliberately weak.** It uses a namespace-scoped ServiceAccount
whose Role has **no `delete` verb on any workload, no write verb on `persistentvolumeclaims`, and
does not name `postgres`, `redis` or `ceph` anywhere** (§2.3). Two of the three landmines in this
stack are therefore enforced by the API server, not by an `if` in a shell script: the updater
*cannot* delete an aggregator PVC and *cannot* restart ceph even if the script has a bug. The root
kubeconfig at `/etc/rancher/k3s/k3s.yaml` is never used by the updater.

### Tier order

```
A  aggregators      4 chan StatefulSets, reddit, nsfw-classifier
B  backend          migration Job  →  sts/maniwani
C  everything else  maniwani-frontend, anubis, tracker, seedbox, clamav,
                    nntp-hub, ergo, rtmp, glados-tts, redlib, coturn
D  edge             nginx                                    ← ALWAYS LAST
```

Least blast radius first, edge last, so an early failure never costs a public outage.

---

## 2. One-time setup

Everything in this section is run **once**, from the software node as `ubuntu`, with
`export KUBECONFIG=/etc/rancher/k3s/k3s.yaml`. After this section you should not need to SSH in
again for routine deploys.

### 2.1 Generate the GitHub deploy key (read-only)

Generate it **on your workstation**, not on the server. The private half never touches GitHub.

```bash
# --- on your workstation ---
umask 077
ssh-keygen -t ed25519 -N '' -C 'maniwani-updater (read-only)' -f ./maniwani-deploy
cat ./maniwani-deploy.pub
```

Then in a browser:

1. `https://github.com/Jonathan-R-Anderson/maniwani/settings/keys` → **Add deploy key**
2. Title: `maniwani-updater (software node, read-only)`
3. Key: paste the contents of `maniwani-deploy.pub`
4. **Leave "Allow write access" UNCHECKED.**

> A **repository deploy key**, not a personal SSH key and not a PAT. A personal key gives the node
> access to every repo you can see. A deploy key **with** write access turns a node compromise
> into a repo compromise — which, given §1, would close the loop into a self-sustaining backdoor.
> Read-only keeps the arrow pointing one way.

Create the Secret. **The Secret is the source of truth; the host keeps no long-lived copy.**

```bash
kubectl -n maniwani create secret generic maniwani-git-deploy-key \
  --from-file=id_ed25519=./maniwani-deploy

shred -u ./maniwani-deploy          # workstation copy destroyed
```

Verify by key name only (prints no key material):

```bash
kubectl -n maniwani get secret maniwani-git-deploy-key -o jsonpath='{.data}' | tr ',' '\n'
# expect exactly:  {"id_ed25519":"..."}
```

**Rotation later is `kubectl`, not SSH** — which is the whole point of the feature:

```bash
kubectl -n maniwani create secret generic maniwani-git-deploy-key \
  --from-file=id_ed25519=./new-key --dry-run=client -o yaml | kubectl apply -f -
```

The updater re-reads the Secret into a tmpfs at the top of every run and shreds it on exit, so a
rotation takes effect on the next timer tick with no restart.

### 2.2 Create the `/_deploy/` Basic-auth Secret

```bash
sudo apt-get install -y apache2-utils          # provides htpasswd
DEPLOY_PW=$(openssl rand -base64 24)
echo "SAVE THIS NOW — it is not recoverable: ops / $DEPLOY_PW"

kubectl -n maniwani create secret generic maniwani-deploy-auth \
  --from-file=htpasswd=<(htpasswd -nbB ops "$DEPLOY_PW")
unset DEPLOY_PW
```

`-B` is bcrypt, which nginx supports and which does not leak to a `ps` snapshot the way `-p`
(plaintext) would. Put the password in your password manager **before** you close the terminal.

### 2.3 ServiceAccount, Role, RoleBinding, status ConfigMap

Save as `k8s/updater/rbac.yaml` and apply. Read the Role — it is a control, not a formality.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: maniwani-updater
  namespace: maniwani
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: maniwani-updater
  namespace: maniwani
rules:
  # --- read-only, collection-wide. list/watch cannot be restricted by name. ---
  - apiGroups: ["", "apps", "batch"]
    resources: ["pods", "pods/log", "services", "configmaps",
                "persistentvolumeclaims", "deployments", "statefulsets",
                "daemonsets", "jobs", "events"]
    verbs: ["get", "list", "watch"]

  # --- the deploy key, and ONLY the deploy key ---
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["maniwani-git-deploy-key"]
    verbs: ["get"]

  # --- mutate ONLY these workloads. -------------------------------------------
  # postgres / redis / ceph are ABSENT BY DESIGN. This is what makes "the
  # updater restarted ceph and the 7 GB data node OOMed" impossible rather
  # than merely unlikely. Do not add them.
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets"]
    resourceNames:
      - maniwani
      - maniwani-frontend
      - anubis
      - nginx
      - fourchan-aggregator
      - eightchan-aggregator
      - sevenchan-aggregator
      - generic-aggregator
      - reddit-aggregator
      - nsfw-classifier
      - redlib
      - rtmp
      - seedbox
      - tracker
      - coturn
      - clamav
      - ergo
      - glados-tts
      - nntp-hub
      - falco
    verbs: ["get", "patch", "update"]        # NO delete. NO create.

  # --- migration / downgrade Jobs ---
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "delete"]

  # --- ConfigMaps the updater may rewrite ---
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames:
      - log-init-script
      - nginx-conf
      - maniwani-cfg
      - anubis-policy
      - scraper-common-env
      - fourchan-aggregator-env
      - eightchan-aggregator-env
      - sevenchan-aggregator-env
      - generic-aggregator-env
      - reddit-aggregator-env
      - nsfw-classifier-env
      - redlib-env
      - maniwani-media-config
      - coturn-start
      - falco-local-rules
      - maniwani-deploy-status
    verbs: ["get", "patch", "update"]

  # --- the wedged-pod nudge (§6.2). Pods only; never PVCs, never workloads. ---
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["delete"]

  # --- NetworkPolicies, so a policy change can ship ---
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: maniwani-updater
  namespace: maniwani
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: maniwani-updater
subjects:
  - kind: ServiceAccount
    name: maniwani-updater
    namespace: maniwani
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: maniwani-deploy-status
  namespace: maniwani
data:
  status.json: |
    {"result":"never-run"}
```

```bash
kubectl apply -f k8s/updater/rbac.yaml
```

**Note there is no `persistentvolumeclaims` write rule and no `delete` on workloads.** That is the
aggregator-PVC landmine, closed at the API server. If a future version of the updater "needs" one
of those verbs, the correct response is to fix the updater, not the Role.

Mint the kubeconfig the updater will use:

```bash
sudo install -d -m 0700 /etc/maniwani-updater

TOKEN=$(kubectl -n maniwani create token maniwani-updater --duration=8760h)
CA=$(sudo base64 -w0 /var/lib/rancher/k3s/server/tls/server-ca.crt)

sudo tee /etc/maniwani-updater/kubeconfig >/dev/null <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: k3s
    cluster: {server: https://127.0.0.1:6443, certificate-authority-data: ${CA}}
contexts:
  - name: updater
    context: {cluster: k3s, namespace: maniwani, user: updater}
current-context: updater
users:
  - name: updater
    user: {token: ${TOKEN}}
EOF
sudo chmod 0600 /etc/maniwani-updater/kubeconfig
unset TOKEN CA
```

Verify the Role is as tight as it claims. **Every line below must print what the comment says:**

```bash
K="sudo kubectl --kubeconfig=/etc/maniwani-updater/kubeconfig -n maniwani"
$K auth can-i patch statefulset/maniwani            # yes
$K auth can-i delete statefulset/maniwani           # no
$K auth can-i patch statefulset/ceph                # no   <-- landmine closed
$K auth can-i patch statefulset/postgres            # no   <-- landmine closed
$K auth can-i delete pvc/aggregator-4chan           # no   <-- landmine closed
$K auth can-i create pvc                            # no
$K auth can-i get secret/maniwani-dotenv            # no
$K auth can-i get secret/maniwani-git-deploy-key    # yes
```

**Set a calendar reminder for 11 months from install.** The token has a 8760h (1 year) lifetime;
when it expires every run fails at the first `kubectl` call with `Unauthorized`, and the fix
(re-run the block above) requires SSH.

### 2.4 The one-time nginx edit that publishes the log

This is the **only** time the updater's install touches the edge. Afterwards the updater merely
writes files into a directory nginx is already serving — which is the property that matters, since
the log-publishing path must not depend on the update succeeding.

**(a)** In `k8s/app/40-nginx.yaml`, add two volumes next to the existing `acme-webroot` hostPath:

```yaml
        - name: deploy-status
          hostPath:
            path: /var/lib/maniwani/deploy
            type: DirectoryOrCreate
        - name: deploy-auth
          secret:
            secretName: maniwani-deploy-auth
            defaultMode: 0444
```

and mount both read-only in the `nginx` container:

```yaml
            - name: deploy-status
              mountPath: /deploy-status
              readOnly: true
            - name: deploy-auth
              mountPath: /etc/nginx/deploy-auth
              readOnly: true
```

**(b)** In `k8s/app/00-configmaps.yaml`, inside the `listen 443 ssl http2;` server block, **above
`location /`** (which is the Anubis-guarded catch-all):

```nginx
            location ^~ /_deploy/ {
                # MUST bypass Anubis: a JS proof-of-work challenge makes this
                # page unreadable from curl and from a browser with cookies
                # cleared -- i.e. unreadable exactly when you need it.
                auth_request off;
                auth_basic "maniwani deploy";
                auth_basic_user_file /etc/nginx/deploy-auth/htpasswd;
                alias /deploy-status/;
                autoindex on;
                default_type text/plain;
                types {
                    text/html  html;
                    application/json json;
                    text/plain log txt;
                }
                add_header Cache-Control "no-store" always;
                add_header X-Robots-Tag  "noindex, nofollow" always;
            }
```

`^~` so it wins over any regex location. `alias` (not `root`) because the URI prefix and the
directory name differ.

**(c)** Create the directory and apply. **This costs one nginx Recreate — a hard 5–15 s outage on
80/443 (§5.4). Do it deliberately, at a quiet hour, not at 3am during an incident.**

```bash
sudo install -d -m 0755 -o root -g root /var/lib/maniwani/deploy
sudo install -d -m 0755 /var/lib/maniwani/deploy/runs
printf 'updater installed, no run yet\n' | sudo tee /var/lib/maniwani/deploy/index.html

kubectl apply -f k8s/app/00-configmaps.yaml
kubectl apply -f k8s/app/40-nginx.yaml
kubectl -n maniwani rollout restart deploy/nginx     # subPath ConfigMap mounts never auto-update
kubectl -n maniwani rollout status  deploy/nginx --timeout=120s

curl -ksS -u ops:<password> https://syndichan.org/_deploy/     # expect the placeholder text
curl -ksS -o /dev/null -w '%{http_code}\n' https://syndichan.org/_deploy/   # expect 401
```

The updater runs as root and writes mode `0644` files; the nginx container is non-root and mounts
read-only, so a compromised edge cannot forge a deploy log.

### 2.5 Host layout, config and the systemd units

```bash
sudo install -d -m 0700 /etc/maniwani-updater
sudo install -d -m 0755 /usr/local/lib/maniwani-updater
sudo install -d -m 0700 /var/lib/maniwani-updater/{render,state}
sudo install -d -m 0755 /var/log/maniwani/updater
```

**Pin GitHub's host keys — do not TOFU them.**

```bash
ssh-keyscan -t rsa,ecdsa,ed25519 github.com | sudo tee /etc/maniwani-updater/known_hosts
sudo chmod 0644 /etc/maniwani-updater/known_hosts
# Cross-check the ed25519 fingerprint against GitHub's published value:
ssh-keygen -lf /etc/maniwani-updater/known_hosts | grep ed25519
# expect: SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
```

**`/etc/maniwani-updater/updater.env`** (mode 0600) — see §11 for every key:

```bash
sudo tee /etc/maniwani-updater/updater.env >/dev/null <<'EOF'
REPO_URL=git@github.com:Jonathan-R-Anderson/maniwani.git
BRANCH=main
DOMAIN=syndichan.org
NAMESPACE=maniwani

MIGRATION_ROLLBACK=auto
REQUIRE_SIGNED=0

TIMEOUT_APP=900
TIMEOUT_AGG=300
TIMEOUT_MEDIA=300
TIMEOUT_EDGE=120

KEEP_RENDERS=10
KEEP_TAGS=4
MIN_FREE_GB=20
EOF
sudo chmod 0600 /etc/maniwani-updater/updater.env
```

**`/etc/systemd/system/maniwani-updater.service`:**

```ini
[Unit]
Description=maniwani GitHub updater
After=network-online.target k3s.service docker.service
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/maniwani-updater/updater.env
Environment=KUBECONFIG=/etc/maniwani-updater/kubeconfig
ExecStart=/usr/local/lib/maniwani-updater/update.sh
# A `maniwani` rebuild (multi-stage, ubuntu:20.04 + node) plus a 900s rollout
# is the long pole. 3600 is headroom, not an expectation.
TimeoutStartSec=3600
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=6

[Install]
WantedBy=multi-user.target
```

**`/etc/systemd/system/maniwani-updater.timer`:**

```ini
[Unit]
Description=poll GitHub for maniwani updates

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
```

**`/etc/systemd/system/maniwani-updater-prune.timer`** — the weekly builder-cache prune, kept
*separate* from the deploy path (§9):

```ini
[Timer]
OnCalendar=Sun 04:30
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
```

with a matching `maniwani-updater-prune.service` running
`ExecStart=/usr/bin/docker builder prune --filter until=336h -f`.

Install `update.sh` (mode 0750, owner root), plus `sqlite3`, which the aggregator snapshot needs:

```bash
sudo apt-get install -y sqlite3 jq
sudo install -m 0750 -o root -g root k8s/updater/update.sh \
     /usr/local/lib/maniwani-updater/update.sh
```

### 2.6 Seed the state so the first run is not a full redeploy

The updater deploys **the diff between `deployed.sha` and `origin/main`**. If `deployed.sha` is
missing it has no previous release to roll back to and no idea what changed. Seed it with the
commit that is *actually running right now*.

```bash
sudo install -d -m 0700 /var/lib/maniwani-updater
sudo git clone git@github.com:Jonathan-R-Anderson/maniwani.git \
     /var/lib/maniwani-updater/repo          # one-off, with your own key present

cd /home/ubuntu/maniwani && git rev-parse HEAD    # the commit production was built from
sudo tee /var/lib/maniwani-updater/state/deployed.sha <<<"<that-sha>"
```

The clone at `/var/lib/maniwani-updater/repo` is **separate from `/home/ubuntu/maniwani` on
purpose.** The server checkout stays hand-edited and operator-owned and is never a deployment
input; coupling the two would make a stray uncommitted edit on the box silently deployable.

Then produce a **baseline render** so the very first failure has something to roll back to. Run
the updater once in dry-run against the current SHA:

```bash
sudo /usr/local/lib/maniwani-updater/update.sh --seed-render
ls /var/lib/maniwani-updater/render/            # expect one directory, named for the SHA
```

> **If you skip this, the first failed deploy has no rollback target and will halt at the gate
> with `no previous render` — safe, but you will be doing §7 by hand.**

### 2.7 Enable and verify

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now maniwani-updater.timer maniwani-updater-prune.timer
sudo systemctl list-timers 'maniwani-updater*'

# Force one run now and watch it
sudo systemctl start maniwani-updater.service
journalctl -u maniwani-updater -f
```

Then confirm the no-SSH path works from your laptop:

```bash
curl -sS -u ops:<password> https://syndichan.org/_deploy/status.json | jq .
# expect: {"result":"no_op", "deployed_sha":"<seeded sha>", ...}
```

---

## 3. Triggering an update without SSH

**The timer polls `origin/main` every 5 minutes. Every control channel is git.**

| you want | what you do | what it actually requires | latency |
|---|---|---|---|
| **deploy** | `git push origin main` | push access to the repo | ≤ 5 min + build time |
| **deploy now** | `git push origin main` | same — there is no "faster". The timer's `RandomizedDelaySec=60` means 0–6 min. | ≤ 6 min |
| **deploy from a browser** | merge a PR into `main` on github.com | GitHub web UI only | ≤ 6 min |
| **pause all deploys** | commit an empty file `k8s/updater/HOLD` and push | push access | next tick |
| **resume** | `git rm k8s/updater/HOLD` and push | push access | next tick |
| **skip one commit** | put `[skip deploy]` anywhere in the commit **subject line** | push access | — |
| **redeploy the same code** | `git commit --allow-empty -m 'redeploy' && git push` | push access | ≤ 6 min |
| **roll back to an older release** | `git revert <bad-sha> && git push` | push access | ≤ 6 min |

**Be honest about what these do and do not give you:**

* **There is no push-button, no webhook, no "deploy" URL.** A webhook would mean opening an inbound
  endpoint that triggers root-level code execution on the software node; polling costs one
  `git fetch` per tick against an unchanged SHA — measured in milliseconds — and has no attack
  surface. This is the right trade for a two-node stack.
* **`git revert` is the correct rollback for a *bad but working* release** (a UI regression, a wrong
  config value). It is a normal forward deploy of the reverted code, so it goes through every gate
  and every check. **It is not the tool for a release that broke the schema** — see §8.
* **A force-push that rewinds `main` is refused, not deployed.** The ancestry gate (§5.2) halts if
  the new SHA is not a descendant of the deployed one. Without that, `push --force` to an older
  commit deploys *old code against a new schema*, which per §8 is a guaranteed crashloop wearing
  the costume of a normal update.
* **`HOLD` is the panic brake.** If something is misbehaving and you are not sure the updater is
  innocent, push `HOLD` first, diagnose second. It takes effect at the next tick without a login.

**What still requires SSH.** Adding a new key to the `maniwani-dotenv` Secret does **not**
(`kubectl create secret ... --dry-run=client -o yaml | kubectl apply -f -` from any machine with a
kubeconfig). Changing `k8s/data/**`, changing a PVC, rebuilding `glados-tts`, or repairing the
updater itself **does** — all four are refused by design and are listed in §12.

---

## 4. Reading the error log without SSH

### The URL

```
https://syndichan.org/_deploy/
```

HTTP Basic, user `ops`, password from §2.2. It is a plain directory index; no JS required, works in
any browser and in `curl`.

| path | what it is |
|---|---|
| `/_deploy/` | index page — result of the last run, big and unambiguous, links to everything below |
| `/_deploy/status.json` | machine-readable state of the last run |
| `/_deploy/latest.log` | full log of the most recent run, success or failure |
| **`/_deploy/latest-failure.log`** | **full log of the most recent FAILED run. This is the one you want at 3am.** It persists after later successful runs. |
| `/_deploy/runs/` | per-run archive, `<UTC-timestamp>-<sha>.log` and `.json` |

`status.json` shape:

```json
{
  "run_id": "20260726T041102Z-a1b2c3d4e5f6",
  "started": "2026-07-26T04:11:02Z",
  "finished": "2026-07-26T04:29:47Z",
  "result": "rolled_back",
  "phase": "ROLLBACK",
  "deployed_sha": "9f8e7d6c5b4a",
  "attempted_sha": "a1b2c3d4e5f6",
  "previous_sha": "9f8e7d6c5b4a",
  "failed_step": "rollout statefulset/maniwani",
  "steps": [
    {"step": "build maniwani",              "result": "ok",     "seconds": 412},
    {"step": "import registry.local/maniwani:ga1b2c3d4e5f6", "result": "ok"},
    {"step": "pg_dump pre-migration",       "result": "ok",     "bytes": 71303168},
    {"step": "job/maniwani-migrate",        "result": "ok",     "seconds": 31},
    {"step": "rollout statefulset/maniwani","result": "FAILED", "seconds": 900}
  ],
  "rollback": {
    "performed": true,
    "schema_downgraded_to": "e8b2d41f7a90",
    "objects_reverted": ["app/10-maniwani.yaml"],
    "result": "ok"
  },
  "next_action": "site is serving on 9f8e7d6c5b4a. Fix the ImportError and push again."
}
```

`result` is one of: `no_op`, `success`, `held`, `halted_gate`, `build_failed`, `rolled_back`,
`ROLLBACK_FAILED`.

> **`ROLLBACK_FAILED` is the only value that means "go to §7 now."** Everything else means the site
> is serving on a known-good SHA and you can read the log at leisure.

### Why here and not in the admin panel

The log must be readable **when the thing that failed is the backend**. During the §8 failure mode
the Flask app is crashlooping — any admin-panel log viewer is down exactly when you need it, as
are the database and, through it, anything that stores logs in Postgres. nginx has no dependency on
Postgres, Redis, ceph or the app; it is rolled last and least often; and it already stays up
serving `@starting` when the backend is dead. It is the only component in the stack that is
reliably alive during every failure this updater can produce.

### Secondary channels — convenience, never authoritative

```bash
# from any machine with a kubeconfig — no SSH
kubectl -n maniwani get cm maniwani-deploy-status -o jsonpath='{.data.status\.json}' | jq .

# on the node, in the existing shared-log tree next to backend/, nginx/, ...
sudo tail -f /var/log/maniwani/updater/updater.log
journalctl -u maniwani-updater -n 200
```

### Redaction, honestly

`kubectl` errors do not print Secret values. The genuine leak vector is
`docker build --progress=plain` output, where a careless `RUN echo $SOMETHING` would surface a
value. The updater greps out lines matching the key names present in `.env` before writing the
log. **That is a mitigation, not a guarantee** — a Dockerfile that deliberately echoes a secret can
still leak it into a run log that is protected only by the Basic-auth password. It is not the
weakest link (see §12.1), but it is real.

---

## 5. What a run actually does

### 5.1 Skip detection

```
git fetch --prune origin main
NEW=$(git rev-parse origin/main); OLD=$(cat state/deployed.sha)
[ "$NEW" = "$OLD" ] && exit 0        # no log entry, no work, no ConfigMap patch
```

288 ticks a day cost one `git fetch` each and nothing else.

### 5.2 Gates — every one halts *before* anything mutates

| # | gate | why it exists |
|---|---|---|
| 1 | **ancestry** — `git merge-base --is-ancestor $OLD $NEW` | refuses a force-push that rewinds `main`; see §3 |
| 2 | **signature** — `git verify-commit $NEW` if `REQUIRE_SIGNED=1` | the only real defence against §1's RCE channel |
| 3 | **HOLD** — `k8s/updater/HOLD` present, or `[skip deploy]` in the subject | operator brake |
| 4 | **data tier** — any change under `k8s/data/**` | **halt, change nothing, log loudly.** ceph on a 7 GB swapless node is the OOM-first suspect and postgres *is* the site. Those three get a human. |
| 5 | **PVC drift** — `kubectl diff` every `kind: PersistentVolumeClaim` in the render | PVC specs are largely immutable and an "update" that recreates `aggregator-4chan` destroys `runtime_settings`, the monitored-board list, retention and the thread registry, **and de-links every already-imported thread**. Belt and braces: the updater also strips all PVC objects out of every apply and has no RBAC to write them. |
| 6 | **bootstrap** — any change under `k8s/bootstrap/**` | namespace / StorageClass / PriorityClass edits are manual |
| 7 | **disk** — `< MIN_FREE_GB` free on `/` | a build that dies on ENOSPC halfway is worse than one that never starts |
| 8 | **lock** — `flock -n /var/lib/maniwani-updater/lock` | no overlapping runs |
| 9 | **previous render exists** | nothing to roll back to ⇒ do not deploy. §2.6. |

Gate 4 is what makes "data tier updated, app tier failed" **unreachable by construction** rather
than merely recoverable — the recovery for that scenario is a restarted ceph mon on a 7 GB node,
which is the last thing you want to be doing unattended.

### 5.3 Change → action map

Computed from `git diff --name-only $OLD..$NEW`.

| changed path | rebuilds | rolls |
|---|---|---|
| `backend/**`, `requirements*` | `maniwani` | migration Job → `sts/maniwani` |
| `frontend/**` | `maniwani-frontend` **and `maniwani`** † | `deploy/maniwani-frontend`, `sts/maniwani` |
| `board_aggregators/fourchan_aggregator_plus/**` | `fourchan-aggregator-plus` **and `maniwani`** † | all **four** chan StatefulSets (one image, four workloads) + `sts/maniwani` |
| `reddit-aggregator/**` | `reddit-aggregator` | `sts/reddit-aggregator` |
| `nsfw-classifier/**` | `nsfw-classifier` | `deploy/nsfw-classifier` |
| `deploy-configs/nginx/**` | `maniwani-nginx` **and `maniwani`** † | `deploy/nginx` (tier D) + `sts/maniwani` |
| `deploy-configs/**` (anything else, incl. `uwsgi.ini`, `maniwani.cfg`) | `maniwani` † | `sts/maniwani` |
| `tracker-server/**`, `seedbox/**`, `rtmp/**`, `clamav/**`, `nntp-hub/**` | that image | that workload |
| `glados-tts/**` | **refused — see below** | — |
| `k8s/app/00-configmaps.yaml` | — | apply the CM, then `rollout restart` **only** the consumers whose key changed |
| `k8s/app/**`, `k8s/aggregators/**`, `k8s/media/**` | — | apply that one file |
| `k8s/data/**`, `k8s/bootstrap/**` | — | **halt** (gates 4, 6) |
| `*.md`, `roadmap/**`, `doc/**`, `browser-extension/**`, `scripts/**` | — | nothing |
| anything else | `maniwani` (catch-all: its build context is the repo root) | `sts/maniwani` |

**† This is not paranoia — it is what `backend/Dockerfile` actually does.** Its build context is
the repository root and it `COPY`s `frontend/` (lines 41–50), `deploy-configs/` (line 63) and
`board_aggregators/` (line 69) into the image. A change to any of those is a change to the
`maniwani` image. A change map that rebuilds only `maniwani-frontend` when `frontend/**` changes
ships a backend whose embedded copy is stale — and the failure is silent.

**`glados-tts` is quarantined.** Its Dockerfile `git clone --depth 1`s upstream at HEAD and curls
two ONNX models from a GitHub release *at build time*. It is not reproducible, it is multi-GB, and
`k8s/bootstrap/README.md` §7.1 already says so. A change under `glados-tts/**` **halts** with an
explicit "rebuild this by hand, off the hot path" message. Rebuilding a non-reproducible multi-GB
image on the node serving live traffic, unattended, at 3am, is a self-inflicted outage.

**ConfigMap → restart is mandatory, not optional.** `nginx.conf` is mounted with
`subPath: nginx.conf`; `/maniwani/.env` and `/maniwani/runtime-config.cfg` likewise. **subPath
mounts never receive ConfigMap or Secret updates — the kubelet does not propagate them.** Applying
the ConfigMap alone does *exactly nothing*. The updater hashes each ConfigMap key and issues
`kubectl rollout restart` only for consumers whose key actually changed.

**`replicas: 0` workloads** — `rtmp`, `coturn`, `redlib`, `nntp-hub` — get their image patched but
no rollout wait; recorded as `patched, not running`. `rollout status` on a zero-replica workload
succeeds immediately, so no special-casing beyond not treating "no pods" as failure.

### 5.4 Order, and the nginx problem

Tiers roll A → B → C → D as in §1. **nginx is tier D and is rolled only if
`deploy-configs/nginx/**`, `k8s/app/40-nginx.yaml`, or the `nginx-conf` ConfigMap key actually
changed.** A backend-only push never touches the edge.

> **Every nginx update is a hard 5–15 s outage on 80/443.** `replicas: 1` + `strategy: Recreate` +
> `hostPort` is correct and must not change: RollingUpdate would deadlock forever, with one
> Running pod holding the hostPort and one Pending pod waiting for it. The `@starting` 503 page
> does **not** help here — nginx *is* the thing that is down, so clients get connection-refused,
> not a friendly page. There is no zero-downtime story without a second Deployment on alternate
> hostPorts and a swap, which is more moving parts than this stack wants.

### 5.5 Rollout timeouts — and why 900s for the backend

`sts/maniwani` has `startupProbe` `periodSeconds: 10 × failureThreshold: 60` = **up to 600 s of
legitimate startup**, and before the probe even begins, `ensure_runtime.py:wait_for_port` blocks up
to **300 s** on a TCP connect to the ceph S3 endpoint. On top of that `initialize_runtime` retries
up to `MANIWANI_STARTUP_RETRIES=30` times.

**`TIMEOUT_APP=900` is a floor, not a preference. Lower it and the updater will roll back healthy
deploys.** Aggregators and media: 300 s. Edge: 120 s.

### 5.6 Smoke test, after tier D

```bash
kubectl -n maniwani exec deploy/nginx -- wget -q -O- -T5 http://maniwani:3032/health
curl -ksS -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" https://127.0.0.1/    # 200|301|302|307
```

The backend check goes to the **Service**, not through the edge: `location /` is behind an Anubis
`auth_request`, so a bare curl would get a challenge and look like a failure.

Only after the smoke test passes does `deployed.sha` advance and the render become the new
rollback baseline.

---

## 6. Automatic rollback

**Primitive:** `kubectl apply -f render/<prev-sha>/<file>` for exactly the files this run applied,
walked in **reverse of the order they were applied**, from an `applied.jsonl` appended to as each
object goes in. Declarative, so it converges; **safe to re-run**; safe to re-run after a crash
mid-rollback. A run records its phase (`GATE / BUILD / MIGRATE / ROLL_A..D / VERIFY / ROLLBACK /
DONE / HALTED`); a later run that finds a non-terminal phase resumes into `ROLLBACK` rather than
starting a fresh deploy.

`kubectl rollout undo` is deliberately **not** used. It fights `kubectl apply`'s field ownership,
has no meaning for a bare ConfigMap, and — critically — restores a pod spec naming a *tag* whose
content may have moved. That last point is the whole reason for the `:g<sha>` scheme:

> `registry.local/x:latest` + `IfNotPresent` + no registry means **overwriting a tag in place is a
> one-way door.** The old bits become unreferenced and unreachable, and `rollout undo` would
> "restore" a pod spec pointing at a tag that now contains the broken image. The updater therefore
> tags every build `registry.local/<name>:g<12-hex-sha>` and patches workloads to that tag, so the
> previous tag still exists in containerd. `:latest` is still moved after a successful build purely
> so that `bootstrap/README.md` §7 and manual `docker build` stay true — **no running workload
> references `:latest` after the first updater run.** The repo manifests keep `:latest` verbatim;
> the updater renders a copy and never applies a repo file directly.

### 6.1 Image build failure

Nothing has been applied. `docker build` exits non-zero → last 200 lines of build output captured,
`docker image prune -f` (dangling only, never `-a`), `:latest` **not** moved, `deployed.sha` **not**
advanced, log written, exit 1. Rollback is a no-op and is logged as such.

Trivial — and it is the most common failure, so it must still produce a readable log or the feature
has failed its requirement. `result: "build_failed"`.

### 6.2 Manifest applies, pods never Ready

`kubectl rollout status <kind>/<name> --timeout=<T>` returns non-zero. The updater then:

```bash
# 1. diagnostics into the log FIRST. This is the whole value of the log file --
#    the pod is about to be replaced and its evidence destroyed.
kubectl -n maniwani describe $KIND/$NAME | tail -60
kubectl -n maniwani logs $KIND/$NAME --all-containers --tail=200
kubectl -n maniwani logs $KIND/$NAME --all-containers --tail=200 --previous
kubectl -n maniwani get events --field-selector involvedObject.name=$NAME \
        --sort-by=.lastTimestamp | tail -30

# 2. revert, in reverse apply order, from the previous render
kubectl apply -f "$RENDER_PREV/$FILE"
kubectl rollout status $KIND/$NAME --timeout=$T
```

**Belt and braces for a wedged StatefulSet.** A `sts/maniwani` pod in `CrashLoopBackOff` or
`ImagePullBackOff` can sit there while the controller waits. If 30 s after the revert apply the
pod's `spec.containers[0].image` still names the new tag, the updater issues a plain
`kubectl delete pod maniwani-0` — **never `--force --grace-period=0`**, which risks a second pod
attaching an RWO volume. The controller replaces it from the reverted template.

### 6.3 Migration ran, backend crashloops

See **§8**. This is the case with real caveats and it gets its own section.

### 6.4 Partial application

* **Data tier vs app tier: cannot happen.** Gate 4 halts before any mutation, and the Role has no
  write verb on `postgres`/`redis`/`ceph`.
* **Within the app tier:** `applied.jsonl` records `{file, kind, name, ts}` per object *as it is
  applied*. Rollback replays that list in reverse against `render/<prev-sha>/` with a
  `rollout status` on each. Tier A succeeded and tier B failed ⇒ **tier A is reverted too**, so the
  cluster lands on exactly one coherent SHA. Never a mixed state.
* **Aggregator SQLite, the sneaky one.** If a new aggregator image migrates its own `.db` in place
  on boot, reverting the image leaves an *upgraded* database under *old* code. Before tier A rolls,
  and only if an aggregator image changed, the updater takes a **consistent** snapshot — not `cp`,
  which tears a live SQLite file:

  ```bash
  sqlite3 "$db" ".backup '$STATE/aggdb/$(echo "$db" | tr / _)'"
  ```

  Restoring is a file copy while the StatefulSet is at `replicas: 0`, and it is **logged as a
  manual step: the updater never writes into a PVC automatically.** The PVCs themselves are never
  deleted, never recreated, never resized.

### 6.5 Idempotency

Rollback is: apply a fixed directory, wait for rollout, repeat. No step's behaviour depends on
current state, so re-running after a partial rollback re-applies specs that are already correct
(no-op) and finishes the rest. `flock` prevents overlap; the phase file makes a crashed run resume
into `ROLLBACK` rather than `DEPLOY`.

**You can safely run `sudo systemctl start maniwani-updater.service` as many times as you like.**

---

## 7. Manual rollback, when the automatic one fails

Reach for this when `status.json` says `"result": "ROLLBACK_FAILED"`, or when the updater itself is
broken (bad `update.sh`, expired token, full disk). **This section requires SSH — by definition:
if the automation could do it, it would have.**

```bash
ssh ubuntu@51.79.71.153
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml     # the ROOT kubeconfig, not the updater's
```

### 7.0 Stop the updater first

Otherwise the next tick fights you.

```bash
sudo systemctl stop maniwani-updater.timer
sudo systemctl stop maniwani-updater.service
```

Re-enable at the very end with `sudo systemctl start maniwani-updater.timer`, and push a `HOLD`
commit if you want the brake to survive a reboot.

### 7.1 Find the good SHA and confirm its images still exist

```bash
cat /var/lib/maniwani-updater/state/deployed.sha        # last SUCCESSFUL release
ls -1t /var/lib/maniwani-updater/render/                # newest first

PREV=<good-sha>
sudo k3s ctr -n k8s.io images ls -q | grep "g${PREV}"
```

> **If that `grep` prints nothing, STOP.** The image was pruned and there is no registry to pull it
> from. Do not patch a workload to a tag that does not exist — with `IfNotPresent` and no registry
> the pod goes to `ImagePullBackOff` with no way out, and you will have turned a bad release into a
> hard outage. Skip to §7.5 (rebuild from source) instead.

### 7.2 Re-apply the previous release, tier by tier

```bash
R=/var/lib/maniwani-updater/render/$PREV

# D first if the edge was touched, so the site comes back before anything else
kubectl apply -f $R/app/40-nginx.yaml
kubectl -n maniwani rollout status deploy/nginx --timeout=120s

# B
kubectl apply -f $R/app/10-maniwani.yaml
kubectl -n maniwani rollout status sts/maniwani --timeout=900s

# A
kubectl apply -f $R/aggregators/
kubectl -n maniwani rollout status sts/fourchan-aggregator  --timeout=300s
kubectl -n maniwani rollout status sts/eightchan-aggregator --timeout=300s
kubectl -n maniwani rollout status sts/sevenchan-aggregator --timeout=300s
kubectl -n maniwani rollout status sts/generic-aggregator   --timeout=300s
kubectl -n maniwani rollout status sts/reddit-aggregator    --timeout=300s

# C
kubectl apply -f $R/app/20-maniwani-frontend.yaml -f $R/app/30-anubis.yaml
kubectl apply -f $R/media/
```

**Do not `kubectl apply -f $R/data/`.** Nothing in the app tier's failure requires touching
postgres, redis or ceph, and ceph on 7 GB with no swap is the OOM-first suspect in this stack.

Re-applying is idempotent: objects already at the right spec are a no-op. Run it twice if you lost
track of where you were.

### 7.3 If a pod is wedged and will not pick up the reverted spec

```bash
kubectl -n maniwani get pod maniwani-0 -o jsonpath='{.spec.containers[0].image}{"\n"}'
# still the NEW tag 30s after the apply? then:
kubectl -n maniwani delete pod maniwani-0            # plain delete
```

**Never `--force --grace-period=0`.** The PVCs are RWO local-path; forcing risks a second pod
trying to attach a volume the first still holds, and `sts/maniwani` at `replicas: 1` is
`replicas: 1` for a reason (`ensure_runtime.py` guards migrations with a per-container file lock at
`/tmp/maniwani_init.lock` — two pods would run `update_db()` concurrently against the same DB).

### 7.4 If the render directory is gone

Fall back to the repo, which still has `:latest` in every manifest:

```bash
cd /var/lib/maniwani-updater/repo
sudo git fetch origin && sudo git checkout $PREV
kubectl apply -f k8s/app/10-maniwani.yaml
```

This pins the workload to `registry.local/maniwani:latest`. **Verify what `:latest` currently
points at before you trust it** — the updater moves it after every successful build, so it may be
the *broken* image:

```bash
sudo docker image inspect registry.local/maniwani:latest  --format '{{.Id}}'
sudo docker image inspect registry.local/maniwani:g$PREV  --format '{{.Id}}'
# if the IDs differ, :latest is NOT the release you want -- fix it first:
sudo docker tag registry.local/maniwani:g$PREV registry.local/maniwani:latest
sudo docker save registry.local/maniwani:latest | sudo k3s ctr -n k8s.io images import -
```

### 7.5 Last resort — rebuild the good SHA from source

```bash
cd /var/lib/maniwani-updater/repo
sudo git checkout $PREV
sudo docker build -f backend/Dockerfile -t registry.local/maniwani:g$PREV .
sudo docker save registry.local/maniwani:g$PREV | sudo k3s ctr -n k8s.io images import -
kubectl -n maniwani set image sts/maniwani maniwani=registry.local/maniwani:g$PREV
kubectl -n maniwani rollout status sts/maniwani --timeout=900s
```

**Never pass `--target dev`** — that stage keeps nodejs, runs as root, and points `MANIWANI_CFG` at
`devmode.cfg` (sqlite + file storage). The prod stage is the default final stage.

### 7.6 Nuclear option — take the app tier down cleanly

If you cannot get a good backend up and you want to stop serving errors:

```bash
kubectl -n maniwani scale deployment,statefulset --replicas=0 -l maniwani.io/group=app
# the edge keeps serving @starting instead of 502s; the data tier is untouched
```

Bring it back with `--replicas=1` on the same selector. See `k8s/OPERATIONS.md` §2.

---

## 8. What is NOT covered: database migrations

**Read this section before your first schema change, not during it.**

### 8.1 The finding, from the code

`backend/docker-entrypoint.sh` (prod branch, no argument) → `python3 ensure_runtime.py` →
`initialize_runtime()` → `update.py:update_db()` → `command.upgrade(revision="head")`, **at pod
boot, in the app container.** So by the time a readiness failure is visible, the schema is already
forward.

Now `backend/update.py:105-124`. The re-stamp guard is:

```python
revision_chain = [marker[0] for marker in SCHEMA_REVISION_MARKERS] + [EARLIEST_REVISION]
...
if stored_revision is None or (
    stored_revision in revision_chain
    and detected_revision in revision_chain
    and revision_chain.index(detected_revision) < revision_chain.index(stored_revision)
):
    command.stamp(...)          # "The stamp is only ever moved forward."
command.upgrade(config=alembic_config, revision="head")
```

After a forward migration, `alembic_version` holds a revision id that **does not exist in the old
image's `migrations/versions/` directory and is not in its `SCHEMA_REVISION_MARKERS` tuple**. The
guard therefore does not fire, and `command.upgrade("head")` asks Alembic to resolve a revision it
has never heard of.

> **Reverting the backend image alone, after a successful forward migration, does not "risk
> incompatibility" — it deterministically crashes at boot with
> `Can't locate revision identified by '<new-rev>'`.** Any runbook that says "just roll the image
> back" is wrong for this codebase.

### 8.2 What the updater does about it

**Migrations are hoisted out of pod boot into a discrete step.** If the diff touches
`backend/migrations/versions/**`:

**1. Record the pre-state, before anything mutates.**

```bash
PREV_REV=$(kubectl -n maniwani exec statefulset/postgres -- \
  sh -c 'psql -qtAX -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
         -c "SELECT version_num FROM alembic_version"')

kubectl -n maniwani exec -i statefulset/postgres -- \
  sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > /var/lib/maniwani-updater/state/$RUN/pre.dump
```

349 MB logical → roughly 60–100 MB in custom format. **If the dump fails, the run aborts before any
mutation. No dump, no migration.**

> Note the absence of `-n public`. The dump **must** include the non-public `analytics` schema:
> `update.py:_detect_schema_revision` infers the Alembic revision from `analytics.*` tables, so a
> `-n public` dump restored later makes the backend re-run the wrong migrations on first boot.
> Plain `pg_dump -d <db>` takes every schema, which is what you want. Verify with
> `pg_restore -l < pre.dump | grep 'SCHEMA - '` — expect **both** `public` and `analytics`.

**2. Run the migration as a Job** — `Job/maniwani-migrate-g<sha>`, using the **new** image with
`args: ["update"]` (that branch of `docker-entrypoint.sh` is `python3 update.py` and nothing else):

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: maniwani-migrate-gSHA
  namespace: maniwani
spec:
  backoffLimit: 0                 # one shot; a retry would replay a partial migration
  ttlSecondsAfterFinished: 86400  # keep the pod a day so its logs are readable
  template:
    metadata:
      labels:
        # (!) LOAD-BEARING. k8s/data/networkpolicy.yaml is FAIL-CLOSED and selects
        # clients by `app: <name>`. Without this the Job's connections to
        # postgres/redis/ceph HANG until SQLALCHEMY_POOL_TIMEOUT -- DNS resolves,
        # the Services exist, and nothing tells you why.
        app: maniwani
    spec:
      restartPolicy: Never
      nodeSelector: {maniwani.io/role: software}
      securityContext: {fsGroup: 1000}
      containers:
        - name: migrate
          image: registry.local/maniwani:gSHA
          imagePullPolicy: IfNotPresent
          args: ["update"]
          volumeMounts:
            - {name: dotenv, mountPath: /maniwani/.env,               subPath: .env,        readOnly: true}
            - {name: cfg,    mountPath: /maniwani/runtime-config.cfg, subPath: maniwani.cfg, readOnly: true}
      volumes:
        - name: dotenv
          secret: {secretName: maniwani-dotenv, defaultMode: 0444, items: [{key: .env, path: .env}]}
        - name: cfg
          configMap: {name: maniwani-cfg, defaultMode: 0444}
```

It does **not** mount the aggregator PVCs. Note that `update.py:__main__` also calls
`update_storage()`, which uploads `static/` to ceph and re-applies bucket policies — hence the
`app: maniwani` label covering ceph:8080 as well as postgres:5432.

**3. Job fails ⇒ cheap, clean failure.** Alembic is per-revision transactional for DDL on Postgres,
so a failed revision rolls itself back. Earlier revisions in the same run *have* committed — the
log records `PREV_REV` and the Job's output so you can see exactly how far it got. The updater
reverts nothing, halts, and logs. **Hoisting the Job out of pod boot is what buys this failure
mode** — without it, the same failure is a CrashLoopBackOff with the schema in an unknown state.

**4. Job succeeds ⇒ roll `sts/maniwani`.**

> **Stated cost, not hidden:** between Job success and rollout completion (~60–120 s) the **old**
> code serves the **new** schema. Additive migrations: invisible. Destructive ones: errors for that
> window. The alternative is scaling the backend to 0 first — a deliberate outage on *every* schema
> change. The window is the better trade, but it is a real one.

### 8.3 If the backend still crashloops after a successful migration

The rollback is **two steps, and the order is counter-intuitive and not optional**:

```bash
# STEP 1 -- downgrade the schema USING THE NEW IMAGE.
# The OLD image does not contain the new revision script and therefore
# physically cannot downgrade it. Reversing these two steps does not work.
kubectl -n maniwani apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata: {name: maniwani-downgrade-RUN, namespace: maniwani}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 86400
  template:
    metadata: {labels: {app: maniwani}}
    spec:
      restartPolicy: Never
      nodeSelector: {maniwani.io/role: software}
      securityContext: {fsGroup: 1000}
      containers:
        - name: downgrade
          image: registry.local/maniwani:gNEWSHA        # <-- the NEW image
          imagePullPolicy: IfNotPresent
          command: ["python3","-c"]
          args:
            - |
              from alembic import command
              from alembic.config import Config
              c = Config("migrations/alembic.ini")
              c.set_main_option("script_location", "migrations")
              command.downgrade(c, "PREV_REV")
          volumeMounts:
            - {name: dotenv, mountPath: /maniwani/.env, subPath: .env, readOnly: true}
      volumes:
        - name: dotenv
          secret: {secretName: maniwani-dotenv, defaultMode: 0444, items: [{key: .env, path: .env}]}
EOF
kubectl -n maniwani wait --for=condition=complete job/maniwani-downgrade-RUN --timeout=300s

# STEP 2 -- only now revert the image
kubectl apply -f /var/lib/maniwani-updater/render/$PREV/app/10-maniwani.yaml
kubectl -n maniwani rollout status sts/maniwani --timeout=900s
```

All **34** revisions in `backend/migrations/versions/` define a `downgrade()`, which is what makes
this viable at all. Two honest caveats:

* **A downgrade is lossy by definition.** `downgrade()` drops the columns and tables the upgrade
  added. Anything written into them since the migration is gone. Exposure is minutes, and the site
  is largely serving `@starting` during a failed rollout, so it is small — **but it is not zero and
  it is not reversible.**
* **Downgrades are untested code.** They exist; nothing in CI proves they run. A downgrade that
  itself fails leaves the schema forward with no working backend — that is §8.4.

`MIGRATION_ROLLBACK` in `updater.env` selects the behaviour:

* **`auto`** *(recommended default)* — do the two steps above. Given §8.1, *not* downgrading means
  the site stays down, so "manual" is only safer in a bookkeeping sense.
* **`manual`** — revert nothing, halt, and print the exact two commands (with `$PREV_REV` and the
  SHAs already filled in) into `/_deploy/latest-failure.log`.

### 8.4 If the downgrade also fails — the updater stops

It does **not** restore `pre.dump`. Restoring is a `--clean --if-exists` of the whole database and
destroys every post, vote, upload and scraped thread since the dump was taken. **That is a human
decision made with eyes open, never an unattended script's.**

The log ends with the exact command, ready to paste:

```
UNRECOVERABLE AUTOMATICALLY. Schema is at <NEW-REV>; no image in containerd can serve it.
Dump taken 2026-07-26T04:11:02Z, PRE-migration, revision <PREV_REV>:
  /var/lib/maniwani-updater/state/<run-id>/pre.dump
RESTORING DESTROYS ALL WRITES AFTER THAT TIMESTAMP.

  kubectl -n maniwani scale sts/maniwani --replicas=0
  kubectl -n maniwani exec -i statefulset/postgres -- \
      sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
      < /var/lib/maniwani-updater/state/<run-id>/pre.dump
  kubectl -n maniwani scale sts/maniwani --replicas=1
  kubectl -n maniwani rollout status sts/maniwani --timeout=900s
```

Do not add `-j` to `pg_restore`: parallel restore cannot read a custom archive from stdin.

### 8.5 What is NOT recoverable, stated plainly

> **There is no schema rollback that preserves data written under the new schema. Full stop.**

Everything in §8 narrows the window and preserves a dump. None of it is a time machine.

Concretely, for the operator:

| you did | what an image rollback gives you |
|---|---|
| pushed code with **no** migration | complete rollback. Nothing to worry about. |
| pushed an **additive** migration (new table / nullable column) | schema stays forward; the downgrade drops what it added; data written into the new columns in the last few minutes is lost. Everything else is intact. |
| pushed a **destructive** migration (drop / rename / type change) | the `downgrade()` recreates the *shape* but **cannot recreate the dropped data**. Only `pre.dump` has it, and restoring it rewinds the whole database. |

**Your job, before a schema change:** take your own dump, so the decision in §8.4 is cheap.

```bash
# Run this yourself before pushing anything under backend/migrations/versions/.
# The updater also takes one automatically -- this is your independent copy,
# kept somewhere the updater's retention cannot delete.
kubectl -n maniwani exec -i statefulset/postgres -- \
  sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > ~/maniwani-pre-$(date -u +%Y%m%dT%H%M%SZ).dump

ls -lh ~/maniwani-pre-*.dump                            # expect ~60-100 M
pg_restore -l ~/maniwani-pre-*.dump | grep 'SCHEMA - '  # MUST list public AND analytics
```

This needs a kubeconfig, not SSH — run it from your laptop.

---

## 9. Retention

Two stores fill: docker's graph (build side) and containerd's `k8s.io` namespace (runtime side).
Both are pruned at the **end of a successful run** and never during a failed one — pruning after a
failure would delete the very tags §7 needs.

### 9.1 Image tags

The keep-set is **computed, never assumed**:

1. Every image referenced by any pod in the cluster, **including init containers**:
   ```bash
   kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' | sort -u
   ```
2. Every `registry.local/*` ref in the last `KEEP_TAGS` render trees (default 4 = current + 3
   rollback targets).
3. `registry.local/*:latest`.

**Rules — allowlist deletion only:**

* Only `registry.local/<name>:g<12-hex>` is ever eligible. Nothing else is ever deleted.
* **Nothing outside `registry.local/` is touched, ever.** Deleting `ceph/daemon:latest` is
  unrecoverable per `bootstrap/README.md` §7.3 — a newer major will not open the existing
  monmap/bluestore. `postgres:17` and `redis` are pinned-by-digest copies that no longer exist
  under those tags upstream.
* **`docker system prune -a` is forbidden in this codebase.** It would delete
  `registry.local/glados-tts`, which cannot be deterministically rebuilt.

```bash
# containerd, runtime side
k3s ctr -n k8s.io images ls -q \
  | grep -E '^registry\.local/[a-z0-9-]+:g[0-9a-f]{12}$' \
  | grep -vxF -f "$KEEPSET" \
  | xargs -r -n1 sudo k3s ctr -n k8s.io images rm
```

`images rm` removes the **reference**; containerd's periodic GC reclaims the now-unreferenced blobs
asynchronously, so `df` will not move immediately. Verify with
`sudo k3s ctr -n k8s.io content ls | wc -l` before and an hour after.

> **The failure to fear is deleting a tag a running pod uses.** With `IfNotPresent` and no registry
> that pod becomes `ImagePullBackOff` on its next restart with no way out — hence keep-set rule 1
> being derived from **live pods**, not from bookkeeping.

Docker side: the same eligible set via explicit `docker image rm <ref>`, plus
`docker image prune -f` (dangling only). The build cache is pruned by a **separate weekly timer**
(`docker builder prune --filter until=336h -f`), never per-run — pruning the cache before a retry
turns a 2-minute rebuild into a 20-minute one.

**Budget.** 12 images × 4 tags is not 48 images: tags of the same image share every unchanged
layer, so N tags ≈ one image plus N−1 deltas. The `MIN_FREE_GB=20` gate is the backstop, and it
fires *before* a build, not after.

Renders are kept for `KEEP_RENDERS=10` SHAs; they are a few hundred KB each.

### 9.2 Log rotation

Performed at the **start** of each run, before anything can fill the disk:

* per-run log truncated at **5 MiB** (`head -c 5242880`; build output is the fat part), with a
  `[TRUNCATED]` marker appended;
* keep the **20** most recent runs, **plus every failed run from the last 90 days**;
* hard cap `runs/` at **200 MiB** — delete oldest-first past that, failures last;
* `latest-failure.log` is never rotated away while it is the most recent failure.

Check it is behaving:

```bash
du -sh /var/lib/maniwani/deploy/runs /var/lib/maniwani-updater/render
ls -1 /var/lib/maniwani/deploy/runs | wc -l
```

---

## 10. Troubleshooting

`K` below is `kubectl -n maniwani`. Everything in the first block needs no SSH.

### 10.1 From your laptop, no SSH

| symptom | likely cause | run this |
|---|---|---|
| site is up but my push did not appear | run not started yet, or `no_op` (only docs changed) | `curl -su ops: https://syndichan.org/_deploy/status.json \| jq '.result,.deployed_sha,.attempted_sha'` |
| `"result":"held"` | `k8s/updater/HOLD` exists, or `[skip deploy]` in the subject | `git rm k8s/updater/HOLD && git commit -m unhold && git push` |
| `"result":"halted_gate"` | see `.failed_step` — data tier, PVC drift, bootstrap, disk, ancestry | `curl -su ops: https://syndichan.org/_deploy/latest-failure.log \| tail -60` |
| `"result":"build_failed"` | Dockerfile or dependency broke | same log; grep for `ERROR` / `The command '/bin/sh -c` |
| `"result":"rolled_back"` | **site is fine, on the previous SHA.** Read `.failed_step` | `curl -su ops: .../latest-failure.log` |
| **`"result":"ROLLBACK_FAILED"`** | **go to §7 now** | SSH required |
| `status.json` timestamp is hours stale | timer stopped, or every run is `no_op` (no log written on no-op) | `curl -su ops: .../index.html` shows last-run time; if truly stale, SSH and `systemctl status maniwani-updater.timer` |
| `/_deploy/` returns 401 forever | wrong password, or `maniwani-deploy-auth` rotated without an nginx restart | re-check the password; `K rollout restart deploy/nginx` |
| `/_deploy/` returns the Anubis challenge page | the `auth_request off;` line is missing from the location block | re-apply §2.4(b) |
| `/_deploy/` 404s | nginx pod predates the hostPath mount | `K rollout restart deploy/nginx` |

### 10.2 On the node

| symptom | likely cause | command |
|---|---|---|
| timer exists but never fires | unit not enabled, or a previous run is still holding `flock` | `systemctl list-timers 'maniwani-updater*'`; `sudo fuser -v /var/lib/maniwani-updater/lock` |
| every run dies at the first `kubectl` | SA token expired (1 year) | `sudo kubectl --kubeconfig=/etc/maniwani-updater/kubeconfig -n maniwani get pods` → `Unauthorized` ⇒ redo §2.3 |
| `Permission denied (publickey)` on fetch | deploy key revoked, or Secret rotated to a key GitHub does not have | `K get secret maniwani-git-deploy-key`; re-add the pub half in GitHub → Settings → Deploy keys |
| `Host key verification failed` | GitHub rotated a host key, or `known_hosts` is empty | `ssh-keyscan github.com` and compare; regenerate per §2.5 |
| build fails `no space left on device` | containerd blobs or builder cache | `df -h /`; `sudo docker builder prune -f`; `sudo k3s ctr -n k8s.io content ls \| wc -l` |
| gate 7 halts on disk every run | `MIN_FREE_GB` too high, or a real leak | `du -sh /var/lib/rancher/k3s /var/lib/docker /var/lib/maniwani-updater/render` |
| pod `ImagePullBackOff` on `registry.local/...` | the tag was pruned, or the import silently failed | `sudo k3s ctr -n k8s.io images ls \| grep registry.local`; re-import per §7.4 |
| `sts/maniwani` rollout times out at 900s | app crash **or** legitimately slow start (ceph unreachable ⇒ 300 s in `wait_for_port`) | `K logs sts/maniwani --tail=200`; look for `CRITICAL: Waiting for Ceph` — if present, the problem is ceph, not the release |
| backend logs `Can't locate revision identified by` | **§8.1** — old image against a new schema | §8.3, and do it in the stated order |
| backend logs `Working outside of application context` | not a deploy failure; see `update.py:125-128` | — |
| pods hang connecting to postgres/redis/ceph, DNS resolves fine | missing `app: maniwani` pod label ⇒ fail-closed NetworkPolicy | `K get pod <name> --show-labels`; the migration Job template in §8.2 has it for a reason |
| nginx will not roll, one pod Running one Pending | someone changed `strategy` to RollingUpdate; hostPort deadlock | `K get pods -l app.kubernetes.io/name=nginx`; revert to `Recreate` + `replicas: 1` |
| edge answers on localhost but the public site is dark | `hostIP: 127.0.0.1` still on the ports array | `sudo ss -lntp \| grep -E ':(80\|443)\b'`; see `k8s/OPERATIONS.md` §3 |
| data node OOM after a deploy | ceph — **and the updater cannot have caused it, it has no RBAC there** | `K describe pod ceph-0 \| grep -i oomkilled` |
| aggregator lost its monitored-board list | its volume was emptied or replaced — **not by the updater** | `K get pvc` → compare `volumeName` and age against `K get pv`; check `runtime_settings` in the `.db` |
| updater ran twice concurrently | `flock` bypassed (someone ran `update.sh` directly) | always use `systemctl start maniwani-updater.service` |

### 10.3 The first four commands, at 3am

```bash
curl -sS -u ops:<pw> https://syndichan.org/_deploy/status.json | jq '.result, .failed_step, .next_action'
curl -sS -u ops:<pw> https://syndichan.org/_deploy/latest-failure.log | tail -80
curl -ksS -o /dev/null -w '%{http_code}\n' https://syndichan.org/
kubectl -n maniwani get pods -o wide | grep -v Running
```

If line 1 says anything other than `ROLLBACK_FAILED`, **the site is serving on a known-good SHA and
you can go back to bed.** Fix it in the morning with a normal push.

---

## 11. Configuration reference

`/etc/maniwani-updater/updater.env`, mode 0600. Changes take effect on the next tick; no restart.

| key | default | meaning |
|---|---|---|
| `REPO_URL` | `git@github.com:Jonathan-R-Anderson/maniwani.git` | SSH remote. **HTTPS is not a fallback** — the repo is private from the cluster's point of view and anonymous HTTPS does not work. |
| `BRANCH` | `main` | tracked branch |
| `DOMAIN` | `syndichan.org` | used by the smoke test's `Host:` header |
| `NAMESPACE` | `maniwani` | |
| `MIGRATION_ROLLBACK` | `auto` | `auto` = downgrade-then-revert (§8.3); `manual` = halt and print the commands |
| `REQUIRE_SIGNED` | `0` | `1` ⇒ `git verify-commit` against `/etc/maniwani-updater/allowed_signers`. **Set this to 1.** It is the only real defence against §12.1. |
| `TIMEOUT_APP` | `900` | **do not lower** — `startupProbe` alone allows 600 s, `wait_for_port` 300 s before it |
| `TIMEOUT_AGG` | `300` | |
| `TIMEOUT_MEDIA` | `300` | |
| `TIMEOUT_EDGE` | `120` | |
| `KEEP_RENDERS` | `10` | rendered manifest trees retained |
| `KEEP_TAGS` | `4` | `:g<sha>` tags retained = current + 3 rollback targets |
| `MIN_FREE_GB` | `20` | gate 7 |

Other paths:

```
/etc/maniwani-updater/kubeconfig          0600  SA token, namespace-scoped (§2.3)
/etc/maniwani-updater/known_hosts         0644  pinned GitHub host keys
/etc/maniwani-updater/allowed_signers     0644  only if REQUIRE_SIGNED=1
/usr/local/lib/maniwani-updater/update.sh 0750  set -euo pipefail
/var/lib/maniwani-updater/repo                  the updater's OWN clone -- never /home/ubuntu/maniwani
/var/lib/maniwani-updater/render/<sha>/         pinned manifest trees; the rollback source of truth
/var/lib/maniwani-updater/state/                deployed.sha, phase, applied.jsonl, pre.dump, aggdb/
/var/lib/maniwani-updater/lock                  flock
/var/lib/maniwani/deploy/                 0755  served read-only by nginx at /_deploy/
/var/log/maniwani/updater/updater.log           tee, alongside backend/ nginx/ per LOGGING.md
```

---

## 12. Known limitations

Each of these is a deliberate refusal. None is a TODO.

1. **Push access to `main` equals root on the software node.** `docker build` runs `RUN` lines as
   root and the repo defines its own Dockerfiles; no sandbox fixes that while keeping the feature.
   Mitigate **upstream**: branch protection on `main`, required review, and `REQUIRE_SIGNED=1`.
2. **No schema rollback preserves data written under the new schema.** §8.5. The best available is
   a pre-migration `pg_dump` plus an Alembic `downgrade()` that drops what the upgrade added.
3. **Reverting the backend image alone after a migration deterministically crashes.** §8.1,
   verified against `update.py:105-124`. Never offered as an option anywhere in this document.
4. **Data-tier updates are refused.** Gate 4 halts and the RBAC Role does not name `postgres`,
   `redis` or `ceph`. ceph on 7 GB with no swap is the OOM-first suspect; restarting it unattended
   to ship a frontend CSS change is indefensible. Apply `k8s/data/**` by hand, at a chosen hour.
5. **Zero-downtime nginx is impossible** with `hostPort` + `Recreate` + `replicas: 1`. Every edge
   update is 5–15 s of refused connections — not a 503 page, refused connections. Mitigated only by
   rolling nginx when nginx actually changed.
6. **`glados-tts` is never rebuilt automatically.** Non-reproducible (upstream cloned at HEAD, ONNX
   models curled from a GitHub release) and multi-GB. A change under `glados-tts/**` halts.
7. **PVC changes of any kind halt**, and the updater has no RBAC to write them. Resizes and
   storage-class moves are manual, with the scrapers stopped.
8. **`.env` / Secret changes are out of band.** Secrets are not in git and the updater can read
   exactly one of them. A commit needing a new key will fail `config-guard` (the init container in
   `app/10-maniwani.yaml`) or crash at boot, get rolled back, and the log will show the `FATAL:`
   line — but you must add the key yourself. That is still `kubectl`, not SSH.
9. **A force-push that rewinds `main` is halted, not deployed.** Gate 1.
10. **Log confidentiality rests on one Basic-auth password and on the build-output redactor.** A
    Dockerfile that deliberately echoes a secret leaks it into a run log. Not the weakest link
    (see 1), but real.
11. **Aggregator SQLite forward-migration is not undone by an image revert.** Snapshotted with
    `sqlite3 .backup` before tier A; restoring is a documented manual step, because **the updater
    never writes into a PVC.**
12. **Multi-node is not handled.** The updater builds and imports on the software node only. Every
    `registry.local/*` image is consumed there; the data node needs none of them. If that ever
    stops being true, this design needs a registry, not a patch.

---

## Appendix A: files in this directory

| file | status | purpose |
|---|---|---|
| `README.md` | **this file** | the authoritative operator guide and specification |
| `rbac.yaml` | create from §2.3 | SA + Role + RoleBinding + status ConfigMap |
| `update.sh` | to be written to §5–§9 | installed to `/usr/local/lib/maniwani-updater/update.sh` |
| `job-migrate.yaml.tmpl` | template in §8.2 | rendered per-SHA, `args: ["update"]` |
| `job-downgrade.yaml.tmpl` | template in §8.3 | rendered with the **new** image and `$PREV_REV` |
| `HOLD` | absent = deploys enabled | commit this file to pause all deploys (§3) |

Every YAML and every command in §2, §7 and §8 is complete and copy-pasteable as written, so this
README stands alone if the sibling files are missing.

### A note on an inconsistency you will hit

`k8s/bootstrap/README.md` §7.1 calls the edge image `registry.local/nginx:latest`. The manifest —
`k8s/app/40-nginx.yaml:374` — says **`registry.local/maniwani-nginx:latest`**, built from
`./deploy-configs/nginx`. **The manifest is authoritative**; the updater uses `maniwani-nginx`.
If you build the edge by hand, use that name or the pod will start on a stale image and you will
lose an hour to it.

### Related documents

* `k8s/bootstrap/README.md` — cluster build, §7 images, §7.3 the third-party pinning rules
* `k8s/OPERATIONS.md` — starting/stopping the stack, the cutover port swap, "things that will bite"
* `LOGGING.md` — the shared `/var/log/maniwani` convention the updater tees into
