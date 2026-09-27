# maniwani updater — the in-cluster (CronJob) implementation

> **The requirement, verbatim:** *"make a way to pull updates from github without me
> needing to log in via ssh. it should try and update but if it fails to then it needs to
> roll back and produce an error log file of what went wrong."*

**Your deploy procedure becomes `git push`. Your failure report is a URL.**

A CronJob on the software node polls `origin/main` every 5 minutes. On a new commit it
renders the manifests with pinned image tags, builds only the images whose build context
changed, imports them into containerd, runs migrations as a discrete Job, rolls the changed
workloads in tier order, verifies, and — on any failure — re-applies the previous render and
reverts the schema. Every run writes a log and a status JSON to a PVC, which the existing
nginx edge serves at `https://<domain>/_deploy/` behind HTTP Basic.

No SSH in the happy path. No SSH to read the failure.

---

## 0. (!) THIS DIRECTORY CONTAINS TWO UPDATERS. PICK ONE.

Two complete, mutually-exclusive implementations of the same feature now live here:

| | **variant A — in-cluster** (this document) | **variant B — host systemd** (`README.md`) |
|---|---|---|
| driver | `CronJob/maniwani-updater`, every 5 min | `maniwani-updater.timer` on the software node |
| the script | ConfigMap `maniwani-updater-script`, key `update.sh` | `update.sh` in this directory → `/usr/local/lib/maniwani-updater/` |
| docker / containerd | mounted sockets in a privileged pod | host-native tools |
| deploy key | Secret volume, kubelet-resolved (**no RBAC on secrets**) | `kubectl get secret` (**needs the commented-out rule 6**) |
| logs live on | PVC `maniwani-updater-state`, `logs/` | hostPath `/var/lib/maniwani/deploy/` |
| nginx wiring | `80-nginx-deploy-status.yaml` (PVC, `subPath: logs`) | hostPath mount described in `README.md` |
| install / fix the updater itself | `kubectl apply` from anywhere | **needs SSH** |

> **DO NOT INSTALL BOTH.** They would both bind `/_deploy/` in nginx with different
> backing volumes, both poll `origin/main`, both hold the same `deployed.sha` concept in
> different places, and both mutate the same workloads with no shared lock. Two updaters
> racing a rollout is strictly worse than no updater.

**What they share, and what is safe either way:** the object names are already aligned —
`maniwani-git-deploy-key`, `maniwani-deploy-auth`, `maniwani-deploy-status`, the
ServiceAccount and Role in `00-serviceaccount-rbac.yaml`, and the `k8s/updater/HOLD` /
`[skip deploy]` brakes. `10-secrets.example.yaml` and `00-serviceaccount-rbac.yaml` apply to
both. `20-pvc.yaml`, `30-configmap-updater.yaml`, `40-cronjob.yaml`, `50-job-manual.yaml`,
`80-nginx-deploy-status.yaml` and the `Dockerfile` are **variant A only**. `60-job-templates.yaml`
and `90-configmap-deploy-status.yaml` are useful to both.

**The one RBAC difference is real, not cosmetic** — see rule 6 in
`00-serviceaccount-rbac.yaml`. Variant A's pod receives its credentials through a kubelet-
resolved Secret volume, so its Role has **no verb on `secrets` at all**. Variant B's systemd
unit has no kubelet doing that for it and must `kubectl get secret` the deploy key, plus
`create` a ConfigMap. Those two rules ship commented out. Uncomment them **only** if you
adopt variant B.

**Why variant A is the one this document argues for:** variant B's own installation, bug
fixes and config rotation all require the SSH login the feature exists to remove. Everything
else in the trade is discussed in §1.

Also note: **`update.sh` at the top level of this directory is variant B's script.** It is
*not* what the CronJob runs — variant A's copy lives inside
`30-configmap-updater.yaml`. Editing one does not affect the other.

---

## Files, in apply order (variant A)

| file | what it is |
|---|---|
| `Dockerfile` | the updater image. Built by hand, twice ever. |
| `00-serviceaccount-rbac.yaml` | SA + Role + RoleBinding. **The security boundary.** |
| `10-secrets.example.yaml` | key inventory. Names only — no material, and not appliable. |
| `20-pvc.yaml` | 20Gi on `maniwani-local`: clone, rollback baselines, dumps, logs. |
| `30-configmap-updater.yaml` | `update.sh` + pinned github.com host keys + allowed-signers. |
| `40-cronjob.yaml` | the poller. **Read its header before applying — it mounts docker.sock.** |
| `50-job-manual.yaml` | manual trigger with `FORCE` / `DRY_RUN` / `REBUILD_GLADOS`. |
| `60-job-templates.yaml` | migration + downgrade Job templates. |
| `80-nginx-deploy-status.yaml` | one-time edge wiring that publishes the log. |
| `90-configmap-deploy-status.yaml` | seed for the kubectl-readable status mirror. |

---

## 1. Where it runs — and the security tradeoff, stated up front

**It is a privileged CronJob in namespace `maniwani` that mounts `/var/run/docker.sock`
and the k3s containerd socket.**

> **Anything that can talk to either socket is root on the software node.** Not
> "elevated" — root. `docker run -v /:/host --privileged` is one API call away, including
> the WireGuard key that reaches the data node. `readOnly: true` on a unix socket restricts
> the *inode, not the conversation*; it is not claimed as a mitigation here.
> `media/90-falco.yaml` says the same thing about the same two sockets.

k3s cannot build images, there is no registry, and the repo defines its own Dockerfiles.
`docker build` and the containerd import are host operations — something must hold those
sockets or the feature cannot exist. The two honest options were:

**(A) this — a privileged CronJob.** One artifact, versioned in git, installed and
controlled entirely with `kubectl` and `git`. Cost: it adds a root-on-node path to a
namespace that *also* runs the public edge, a Flask app with an upload/image-proxy/scraper
attack surface, and seven scrapers that parse hostile HTML. Anyone who obtains `create pods`
in this namespace gets the node. It is also a standing Falco false positive.

**(B) a host systemd oneshot + timer** (the sibling `README.md`). No new root-on-node path
inside the cluster; not subject to eviction mid-rollout. Cost: the updater itself lives
outside git and outside kubectl, so installing it, fixing a bug in it, or rotating its
config **needs the SSH login this feature exists to remove** — and it needs a long-lived SA
token in a file on disk, a credential variant A never creates.

**(A) is what these manifests ship, because (B) reintroduces the exact problem the user
asked to remove.** If you adopt (B), revisit the `create jobs` grant: with the socket gone
it becomes the largest remaining privilege rather than a rounding error.

**What no arrangement fixes:**

> **This is a remote-code-execution channel from GitHub `main` to root on the software
> node.** `docker build` executes `RUN` lines as root at build time. No sandbox changes that
> while the repo defines its own images.

The mitigation is upstream, not isolation: **branch protection on `main`, required review,
and `REQUIRE_SIGNED=1`** with a filled-in `allowed_signers`. Turn them on.

**Narrowing that is real,** enforced by the API server rather than by an `if` in a shell
script (`00-serviceaccount-rbac.yaml`):

* no verb on `secrets` **at all** — both credentials arrive by kubelet-resolved
  volume/`secretKeyRef`, so a shell injection in `update.sh` cannot enumerate the 114-key
  `maniwani-env`
* no write verb on `persistentvolumeclaims` → **cannot destroy scraped content**
* `postgres` / `redis` / `ceph` absent from every `resourceNames` list → **cannot restart
  ceph** on the 7 GB node
* no `delete` and no `create` on any workload
* `/etc/rancher/k3s/k3s.yaml` (cluster-admin) is never mounted or read

The one unrestricted mutation is `create jobs`, which in practice equals "can read every
Secret in namespace `maniwani`" (a Job's pod spec can mount any of them and the kubelet
resolves it). It is unavoidable — hoisting alembic into a discrete Job is what makes a bad
migration cheap — and next to the docker socket it is a rounding error.

---

## 2. GitHub authentication — read-only deploy key

The remote is `git@github.com:Jonathan-R-Anderson/maniwani.git` over SSH and the repo is
**private from the cluster's point of view**.

> **Anonymous HTTPS does not work and is not a fallback.** An in-cluster Job has no SSH key
> unless you give it one. `update.sh` sets `GIT_TERMINAL_PROMPT=0` so a missing credential
> fails fast instead of hanging until `activeDeadlineSeconds`.

Use a **repository deploy key** — not a user SSH key (access to every repo the account can
reach), not a PAT (broader, and it expires at 3am).

> **"Allow write access" must stay unchecked.** Push access to `main` is already equivalent
> to root on the node (§1). A write-capable key makes the arrow point both ways, so a node
> compromise becomes a repo compromise and poisons every future deploy.

```bash
umask 077; d="$(mktemp -d)"; cd "$d"
ssh-keygen -t ed25519 -N '' -C 'maniwani-updater (read-only)' -f deploy
cat deploy.pub            # paste into GitHub → Settings → Deploy keys. WRITE ACCESS OFF.
kubectl -n maniwani create secret generic maniwani-git-deploy-key --from-file=id_ed25519=deploy
shred -u deploy deploy.pub; cd /; rmdir "$d"
```

The Secret is the source of truth; nothing persists to the node. Rotation is
`create secret … --dry-run=client -o yaml | kubectl apply -f -` — **no SSH**, which is the
whole point.

Host verification is **pinned, not TOFU**: `known_hosts` ships in
`30-configmap-updater.yaml` and the script runs ssh with `StrictHostKeyChecking=yes` plus
`IdentitiesOnly=yes` (without which ssh offers every key it can find and GitHub closes the
connection as "Permission denied (publickey)").

The clone lives on the PVC at `/state/repo` and is **completely separate from
`/home/ubuntu/maniwani`**. The server checkout stays hand-edited and operator-owned, and is
never a deployment input — coupling them would make a stray uncommitted edit on the box
silently deployable.

---

## 3. Install

### 3.1 Prerequisites
`maniwani-env` and `maniwani-dotenv` exist (bootstrap README §5); `k8s/app/00-configmaps.yaml`
is applied; the software node is labelled `maniwani.io/role=software`; `command -v k3s`
returns `/usr/local/bin/k3s` (if not, fix the `k3s-bin` hostPath in `40-cronjob.yaml`).

### 3.2 Build the updater image (on the software node, once)
```bash
cd /home/ubuntu/maniwani
docker build -t registry.local/maniwani-updater:latest ./k8s/updater
docker save   registry.local/maniwani-updater:latest | sudo k3s ctr images import -
docker run --rm registry.local/maniwani-updater:latest -lc 'pg_dump --version; yq --version'
```
The `pg_dump` major **must be ≥ the postgres server major** (17). A 16 client refuses with
`server version 17, pg_dump version 16`, which surfaces as "refusing to migrate without a
restore point".

### 3.3 Apply
```bash
kubectl -n maniwani create secret generic maniwani-git-deploy-key --from-file=id_ed25519=…  # §2
kubectl -n maniwani create secret generic maniwani-deploy-auth   --from-file=htpasswd=…     # §6

kubectl apply -f k8s/updater/00-serviceaccount-rbac.yaml
kubectl apply -f k8s/updater/20-pvc.yaml
kubectl apply -f k8s/updater/30-configmap-updater.yaml
kubectl apply -f k8s/updater/60-job-templates.yaml
kubectl apply -f k8s/updater/90-configmap-deploy-status.yaml
kubectl apply -f k8s/updater/40-cronjob.yaml     # read its header first

# assert the DENIALS, not just the grants — all four must answer "no"
S=system:serviceaccount:maniwani:maniwani-updater
for q in "patch statefulset/postgres" "delete pvc/aggregator-4chan" "get secrets" "create deployments"; do
  echo -n "$q -> "; kubectl auth can-i $q -n maniwani --as=$S
done
```

Then wire the edge (§6) — one deliberate 5–15 s outage — and **commit that change into
`k8s/app/40-nginx.yaml` and `00-configmaps.yaml`**, or the first deploy that touches the edge
will silently delete `/_deploy/`.

### 3.4 The first run seeds; it does not deploy

With no `state/deployed.sha` the updater adopts `origin/main` as its rollback baseline,
renders it, and applies **nothing** (`result: "seeded"`).

> **Make sure the cluster actually matches `main` at that moment.** The baseline is what
> every future rollback targets; seeding against a cluster that is three commits behind means
> the first rollback rolls *forward* into untested territory.

---

## 4. What "update" means

### 4.1 Skip detection
`git fetch`; if `origin/main` is unchanged the run exits with no log entry and no work.
288 pollings/day cost 288 fetches.

### 4.2 Gates — every one halts before anything is mutated

| gate | why |
|---|---|
| **ancestry** (`merge-base --is-ancestor`) | a force-push that rewinds `main` would deploy **old code against the new schema** — a guaranteed crashloop (§5.3) dressed as a normal update |
| **signature** (`REQUIRE_SIGNED=1`) | the only real defence against §1's RCE channel |
| **HOLD** | `k8s/updater/HOLD` in the repo, or `[skip deploy]` in the commit subject |
| **data tier** | any change under `k8s/data/**` → **halt.** ceph on a 7 GB swapless node is the OOM-first suspect; postgres *is* the site |
| **bootstrap tier** | `k8s/bootstrap/**` is cluster-scoped; the Role has no cluster permissions |
| **PVC drift** | a changed PVC would recreate `aggregator-4chan` and destroy `runtime_settings`, the monitored-board list, retention and the thread registry — **every already-imported thread de-links** |
| **unwritable kinds** | Services, NetworkPolicies, Secrets… changed → halt rather than 403 halfway through a multi-doc file |
| **new object** | the Role has no `create`; adding a workload is a human `kubectl apply` |
| **disk** | `< 20 GB` free → halt. A build that dies on ENOSPC halfway is worse than one that never starts |
| **flock** | one run at a time, covering hand-made Jobs that `concurrencyPolicy` does not |

The PVC gate is a **text comparison of two rendered trees**, deliberately *not* `kubectl
diff` — `kubectl diff` is a server-side dry run authorized exactly like the real write, so
using it would require the `patch` grant on PVCs the whole design refuses.

### 4.3 Image tagging — `:g<sha>`, and nothing live references `:latest`

`registry.local/<n>:latest` + `IfNotPresent` + no registry makes overwriting a tag in place a
**one-way door**: the old bits become unreachable, and `kubectl rollout undo` would restore a
pod spec naming a tag whose *content* already changed — i.e. it would silently roll back to
the broken image.

So each build is tagged `registry.local/<n>:g<12-hex-sha>`, and the updater renders the
manifest tree with one auditable `sed` that touches only `registry.local/*`. Third-party pins
(`ceph/daemon`, `postgres:17`, `ghcr.io/techarohq/anubis:v1.25.0`, `alpine:3.20`) are never
rewritten — bootstrap README §7.3 is explicit that a `ceph/daemon` that moves majors will not
open the existing monmap. The repo manifests keep `:latest` verbatim so they stay
hand-appliable; `:latest` is still moved after a successful build purely so §7 of the
bootstrap README stays true.

Rollback is therefore a byte-identical re-apply of `render/<prev-sha>/`, which still names
tags that still exist in containerd (the pruner protects the last 4).

### 4.4 Change → action

| changed | rebuild | roll |
|---|---|---|
| `backend/**`, `deploy-configs/uwsgi*`, `requirements*` | `maniwani` | migration Job → `sts/maniwani` |
| `frontend/**` | `maniwani-frontend` | `deploy/maniwani-frontend` |
| `board_aggregators/**` | `fourchan-aggregator-plus` | **all four chan StatefulSets** (one image, four workloads) |
| `reddit-aggregator/**`, `nsfw-classifier/**` | matching | matching |
| `tracker-server/`, `seedbox/`, `rtmp/`, `clamav/`, `nntp-hub/` | matching | matching |
| `deploy-configs/nginx/**` | `maniwani-nginx` | `deploy/nginx` (last) |
| `glados-tts/**` | **refused** | — |
| `k8s/{app,aggregators,media}/<file>` | — | that file |
| `k8s/data/**`, `k8s/bootstrap/**` | — | **halt** |
| `*.md`, `roadmap/`, `doc/`, `browser-extension/` | — | nothing |
| anything else | `maniwani` (its build context is the repo root) | `sts/maniwani` |

**`glados-tts` is quarantined.** Its Dockerfile `git clone --depth 1`s upstream at HEAD and
curls ONNX models from a GitHub release *at build time*. It is not reproducible and it is
multi-GB. Rebuilding it unattended at 3am on the node serving live traffic is a
self-inflicted outage. `REBUILD_GLADOS=1` on a manual Job overrides, once.

**ConfigMap → restart is mandatory, not bookkeeping.** `nginx.conf`, `maniwani.cfg` and
`.env` are mounted with `subPath`, and **a subPath mount never receives ConfigMap updates** —
the kubelet does not propagate into it. Applying the ConfigMap alone does *nothing* until the
pod restarts. The updater hashes each key and restarts only the consumers whose key actually
changed.

`replicas: 0` workloads (`rtmp`, `coturn`, `redlib`) get their image patched; `rollout
status` returns immediately and "no pods" is not treated as failure.

### 4.5 Order, and the nginx problem

```
A  aggregators (4 chan + reddit + nsfw-classifier)
B  migration Job → sts/maniwani
C  frontend, anubis, tracker, seedbox, clamav, nntp-hub, ergo, rtmp
D  nginx                                            ← always last
```

Least blast radius first, edge last, so an early failure never costs a public outage.

`deploy/nginx` is `replicas: 1` + `strategy: Recreate` + `hostPort`. That is **correct and
must not change** — RollingUpdate deadlocks forever with one Running pod holding the hostPort
and one Pending. The consequence is unavoidable:

> **Every nginx update is a hard 5–15 s outage on 80/443.** The `@starting` 503 page does not
> help — nginx *is* what is down, so clients get connection-refused, not a friendly page.
> Zero-downtime would need a second Deployment on alternate hostPorts and a swap: more moving
> parts than this stack wants.

So the edge is rolled **only when the edge changed**. A backend-only push never touches it.

### 4.6 Timeouts

`sts/maniwani`: **900 s**, not 300. Its `startupProbe` alone allows 600 s (10 s × 60), and
`ensure_runtime.py` blocks up to 300 s on a TCP connect to ceph before that. A shorter
timeout rolls back *healthy* deploys. Aggregators/media 300 s; nginx 120 s.

### 4.7 Smoke test

`http://maniwani:3032/health` via the **Service, not the edge** — `location /` sits behind an
Anubis `auth_request`, so a bare curl would collect a 401 and look like a failure. Then the
edge with the real SNI (`--resolve $DOMAIN:443:<nginx ClusterIP>`), because the domain guard
rejects a bare-IP request with `ssl_reject_handshake` — that is the guard working.

`deployed.sha` advances only after both pass.

---

## 5. Rollback

**Primitive:** re-apply `render/<prev-sha>/<file>` for exactly the objects this run applied,
in **reverse of application order**, from an `applied.jsonl` appended to as each object goes
in. Declarative, so it converges — **idempotent and safe to re-run**, including after a crash
mid-rollback. A phase file records `GATE / BUILD / MIGRATE / ROLL_A..D / VERIFY / ROLLBACK /
DONE / HALTED`; a run that finds a non-terminal phase resumes into `ROLLBACK` rather than
starting a new deploy.

`kubectl rollout undo` is deliberately **not** used: it fights `apply`'s field ownership, is
meaningless for a bare ConfigMap, and restores a pod spec naming a tag whose content may have
moved.

### 5.1 Image build failure
Nothing has been applied. Capture the last 400 lines of build output, `docker image prune -f`
(**dangling only, never `-a`**), do not move `:latest`, do not advance `deployed.sha`, write
the log, exit 1. Rollback is a logged no-op. Trivial — and it is the most common failure, so
an unreadable log here fails the requirement outright.

### 5.2 Applies, but pods never Ready
`rollout status` returns non-zero → `describe`, `logs --tail=200`, `logs --previous`, and
sorted events go into the log **first** (that capture is the entire value of the file). Then
re-apply the previous render and wait.

Belt-and-braces: a StatefulSet pod wedged in `CrashLoopBackOff`/`ImagePullBackOff` is not
always replaced promptly by a template change, so after 30 s a pod still reporting the new tag
is deleted — **plain `delete`, never `--force --grace-period=0`**, which risks a second writer
on an RWO volume.

### 5.3 Migration ran, backend crashloops — the honest section

**A finding from the code, not a hypothesis.** `docker-entrypoint.sh` (prod branch) →
`ensure_runtime.py` → `update.py:update_db()` → `command.upgrade("head")`, at pod boot. And
`update.py:105-122` only ever moves the alembic stamp *forward*:

```python
revision_chain = [m[0] for m in SCHEMA_REVISION_MARKERS] + [EARLIEST_REVISION]
if stored_revision is None or (stored_revision in revision_chain
        and detected_revision in revision_chain
        and revision_chain.index(detected_revision) < revision_chain.index(stored_revision)):
    command.stamp(...)          # "The stamp is only ever moved forward."
command.upgrade(config=alembic_config, revision="head")
```

After a forward migration, `alembic_version` holds a revision that **does not exist in the old
image's `migrations/versions/`** and is not in its markers. The guard does not fire, and
`upgrade("head")` asks Alembic to resolve a revision it has never heard of:

```
Can't locate revision identified by '<new>'
```

> **Reverting the backend image alone after a successful migration does not "risk
> incompatibility" — it deterministically crashes at boot.** Any design that says "roll the
> image back and you're fine" is wrong for this codebase.

**(a) Migrations are hoisted out of pod boot.** If the diff touches
`backend/migrations/versions/**`:

1. Record `PREV_REV`, then `pg_dump -Fc` (349 MB logical → ~60–100 MB). **If the dump fails,
   the run aborts before any mutation. No dump, no migration.**
2. Run `Job/maniwani-migrate-g<sha>` on the **new** image with `args: ["update"]`,
   `backoffLimit: 0`, and **no aggregator PVCs mounted**.
3. Job fails with `alembic_version` unchanged → the cheap, clean failure. Revert nothing,
   halt, log. Hoisting the Job is what buys this.
4. Job succeeds → roll `sts/maniwani`.

   *Stated cost:* for ~60–120 s the **old** code serves the **new** schema. Additive
   migrations: invisible. Destructive ones: errors for that window. The alternative is scaling
   the backend to 0 on every schema change. The window is the better trade, but it is real.

**(b) If the backend still crashloops**, rollback is **two steps and order-critical**, and
step one is counter-intuitive:

1. **Downgrade the schema using the NEW image.** The old image does not contain the new
   revision script and physically cannot downgrade it. Not optional.
2. *Only then* re-apply the previous manifest.

All 35 revisions define a `downgrade()`, which is what makes this viable. Two caveats, both
real:

* **A downgrade is lossy by definition.** It drops what the upgrade added; anything written
  into those columns since is gone. Exposure is minutes, and the site was largely serving
  `@starting` — but it is not zero and not reversible.
* **Downgrades are untested code.** They exist; nothing in CI proves they run.

`MIGRATION_ROLLBACK=auto` (default) does the two-step. `manual` reverts nothing and prints the
exact commands into the web log. Given the finding above, *not* downgrading means the site
stays down — `manual` is safer only in a bookkeeping sense.

**(c) If the downgrade also fails, the updater stops.** It does **not** restore the dump: that
is a `DROP`/recreate of the whole database and destroys every post, vote and upload since it
was taken. The log ends with the literal `pg_restore` sequence, ready to paste.

> **Not recoverable, plainly: there is no schema rollback that preserves data written under
> the new schema.** Full stop. The dump and the `downgrade()` narrow the window; neither is a
> time machine.

### 5.4 Partial application

* **Data tier vs app tier: cannot happen.** The gate halts before any mutation if
  `k8s/data/**` changed, *and* the Role cannot patch `postgres`/`redis`/`ceph`. Designed out
  rather than recovered from, because the recovery — a restarted ceph mon on a 7 GB swapless
  node — is the thing you least want to be doing unattended.
* **Within the app tier:** `applied.jsonl` is replayed in reverse against
  `render/<prev-sha>/`. Tier A green + tier B failed → **tier A is reverted too**, so the
  cluster lands on exactly one coherent SHA. Never a mixed state.
* **Aggregator SQLite, the sneaky one.** If a new aggregator image migrates its own `.db` on
  boot, reverting the image does not undo it. Before tier A the updater takes a *consistent*
  `sqlite3 .backup` snapshot (not `cp` — a hot copy of a live SQLite file tears), reading
  through `mode=ro` on read-only mounts. **Restoring is a documented manual step** with the
  StatefulSet at `replicas: 0`: the updater never writes into a PVC, never deletes one, never
  resizes one.

---

## 6. The error log, readable without SSH

The failure this log most has to explain is "the backend updated and now it crashloops". In
that state the Flask app is **down**, so an admin-panel viewer or a DB-backed audit table is
unavailable exactly when needed. **Anything that depends on the backend is disqualified by
construction.**

nginx is the only component with the right dependency shape: no dependency on postgres, redis,
ceph or the app; already serves `@starting` while the backend is dead; rolled last and least
often. So: the updater writes plain files to the PVC, and nginx serves `logs/` read-only at
`/_deploy/` behind HTTP Basic.

```
/_deploy/index.html                 last 40 runs
/_deploy/status.json                machine-readable current state
/_deploy/latest.log                 most recent run
/_deploy/latest-failure.log         THE ONE THAT MATTERS — sticky; a later success
                                    does not erase it
/_deploy/runs/<ts>-<sha>.log
```

Wiring is a **one-time** edit (`80-nginx-deploy-status.yaml`), costing one nginx Recreate. Two
details that are load-bearing:

* the mount uses **`subPath: logs`** — the PVC also holds pg_dumps, and `alias`ing the volume
  root would publish a full database dump behind one password
* the location block sets **`auth_request off`** — it must bypass Anubis, or a JS
  proof-of-work challenge makes the log unreadable from curl and from a freshly-cleared
  browser, which is every situation it exists for. That is why `auth_basic` is mandatory
  rather than belt-and-braces.

**After install the updater never edits nginx to publish a log** — it only writes files into a
directory nginx already serves. That is the property that matters: the log-publishing path has
zero dependency on the update succeeding.

Secondary, never authoritative: `kubectl -n maniwani get cm maniwani-deploy-status -o
jsonpath='{.data.status\.json}'` (capped at 60 KB — a ConfigMap has a ~1 MiB ceiling).

**Redaction** scrubs the postgres password and credential-shaped `KEY=value` lines. The real
leak vector is `docker build --progress=plain` output. It is a mitigation, not a guarantee —
and not the weakest link, since anyone who can push a Dockerfile can already read those
secrets by other means.

**Rotation runs at the *start* of each run**, so a disk-full failure cannot also block its own
cleanup: 5 MiB per run log, 20 most recent runs, every failure from the last 90 days, 200 MiB
hard cap on `runs/` (oldest first, failures last).

---

## 7. Retention

Pruned only at the **end of a successful run**, never after a failure — the previous tag is
the rollback target.

**Keep-set, computed rather than assumed:** every image referenced by any pod in the cluster
(including init containers, derived from **live pods**), every `registry.local/*` ref in the
last 4 render trees, and `:latest`.

**Allowlist deletion only.** Only `registry.local/<n>:g<12hex>` is ever eligible.

> **`docker system prune -a` is forbidden in this codebase.** It would delete
> `registry.local/glados-tts`, which cannot be deterministically rebuilt. Nothing outside
> `registry.local/` is touched, ever: deleting `ceph/daemon` is unrecoverable, and
> `postgres:17`/`redis` are pinned copies that no longer exist under those tags upstream.

`ctr images rm` drops the *reference*; containerd's GC reclaims blobs asynchronously, so `df`
will not move immediately. Deleting a tag a running pod uses is the failure to fear — with
`IfNotPresent` and no registry it becomes a permanent `ImagePullBackOff` with no way out,
which is why keep-set rule 1 comes from live pods.

12 images × 4 tags is not 48 images: tags of one image share every unchanged layer. The
`< 20 GB free` gate is the backstop.

---

## 8. Day-to-day

| action | command |
|---|---|
| deploy | `git push` (≤5 min) |
| deploy now | `kubectl -n maniwani create job --from=cronjob/maniwani-updater updater-manual-$(date +%s)` |
| what would this do? | edit `50-job-manual.yaml` with `DRY_RUN=1`, then `kubectl -n maniwani create -f` |
| pause | `kubectl -n maniwani patch cronjob maniwani-updater -p '{"spec":{"suspend":true}}'` — or commit `k8s/updater/HOLD`, which works with git alone |
| skip one commit | `[skip deploy]` in the subject |
| what happened | `https://<domain>/_deploy/` |

---

## 9. Test plan — run each on the live cluster, on a scratch branch, then fast-forward

All four leave the site serving.

1. **Build failure.** Push `RUN false` into `backend/Dockerfile`. Expect: gates pass, build
   fails, **zero kubectl mutations** (`kubectl -n maniwani get sts maniwani -o
   jsonpath='{…image}'` unchanged), `deployed.sha` unchanged, `latest-failure.log` shows the
   `RUN false` output, `result == "build_failed"`. Re-run: identical, no drift.
2. **Rollout timeout.** Change `deploy-configs/uwsgi.ini` so `/health` never answers. Expect:
   build OK, image imported as `:g<sha>`, `sts/maniwani` applied, timeout at 900 s,
   describe/logs/events captured, previous render re-applied, pod back on `:g<prev>`,
   `/health` green, **edge never touched** (tier D skipped). Then re-run the rollback by hand:
   converges, no change.
3. **Migration + crashloop.** Push (a) a real additive migration and (b) an `ImportError` in a
   module imported at app init. Expect: `pre.dump` written, migration Job succeeds,
   `alembic_version` advances, backend crashloops, rollback runs the **downgrade Job on the
   new image** to `$PREV_REV`, then re-applies the old manifest, and the old backend boots
   clean. **Verify explicitly that skipping the downgrade produces `Can't locate revision
   identified by …`** — that assertion justifies the whole ordering and should be a permanent
   test, not a one-off.
4. **Partial application.** Push a commit touching `board_aggregators/` (tier A, succeeds)
   *and* `backend/` (tier B, broken). Expect: tier A green, tier B fails, rollback reverts
   **all four chan StatefulSets plus reddit** as well as the backend. Then confirm the
   landmine: `kubectl -n maniwani get pvc` shows all five aggregator PVCs `Bound` with
   unchanged `volumeName` and creation timestamps, and each scraper's monitored-board count in
   its admin card is unchanged.
5. **Data-tier gate.** Whitespace change to `k8s/data/ceph.yaml`. Expect: halt before any
   mutation, ceph pod `startTime` unchanged, log names the file and why.
6. **No-op.** README-only change. Expect: no build, no apply, `result == "no_op"`,
   `deployed.sha` advances.

---

## 10. Flagged — what this will not do, and why

1. **Schema rollback preserving data written under the new schema.** Impossible. Best
   available is a pre-migration dump plus a `downgrade()` that drops what the upgrade added.
2. **Reverting the backend image alone after a migration.** Deterministically crashes (§5.3,
   verified in `update.py:105-122`). Never offered.
3. **Automatic data-tier updates.** Refused at the gate and unreachable via RBAC.
4. **Zero-downtime nginx.** Impossible with `hostPort` + `Recreate` + `replicas: 1`. Every
   edge update is 5–15 s of refused connections; mitigated by rolling it only when it changed.
5. **`glados-tts` automatic rebuild.** Refused: non-reproducible, multi-GB, on the node serving
   live traffic.
6. **PVC changes of any kind.** Halt, and no RBAC to write them. Resizes and storage-class
   moves are manual, with the scrapers stopped.
7. **`.env` / Secret changes.** Not in git. A commit needing a new key fails `config-guard` or
   crashes at boot, gets rolled back, and the log shows the `FATAL:` line — but the operator
   must add the key out of band (`kubectl create secret … | kubectl apply -f -`, which is
   still not SSH).
8. **New workloads.** The Role has no `create`; adding a service is a human apply plus a name
   in the `resourceNames` allowlist.
9. **The RCE channel.** Push access to `main` equals root on the software node. Unavoidable
   given repo-defined Dockerfiles. Mitigate with branch protection, required review and
   `REQUIRE_SIGNED=1` — not with sandboxing.
10. **Log confidentiality** rests on the Basic-auth password and the build-output redactor. A
    Dockerfile that deliberately echoes a secret can leak it into a run log. Real, but not the
    weakest link (see 9).
11. **Aggregator SQLite forward-migration.** An image revert does not undo it. Snapshotted with
    `sqlite3 .backup` before tier A; restoring is a documented manual step, because the updater
    will not write into a PVC.
12. **The updater does not update itself.** `k8s/updater/**` changes are logged as a NOTICE and
    skipped, and the Role has no verbs on `cronjobs`. A self-replacing updater that ships a
    broken version of itself is unrecoverable without SSH.
13. **Running both variants at once** (§0). They would fight over `/_deploy/`, over
    `origin/main`, and over the same workloads with no shared lock.
